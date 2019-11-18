package com.cx.restclient;

import com.cx.restclient.common.Waiter;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.Status;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.httpClient.CxHttpClient;
import com.cx.restclient.osa.dto.*;
import com.cx.restclient.osa.utils.OSAUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;
import org.whitesource.fs.ComponentScan;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;

import static com.cx.restclient.cxArm.dto.CxProviders.OPEN_SOURCE;
import static com.cx.restclient.cxArm.utils.CxARMUtils.getProjectViolatedPolicies;
import static com.cx.restclient.httpClient.utils.ContentType.CONTENT_TYPE_APPLICATION_JSON_V1;
import static com.cx.restclient.httpClient.utils.HttpClientHelper.convertToJson;
import static com.cx.restclient.osa.utils.OSAParam.*;
import static com.cx.restclient.osa.utils.OSAUtils.writeJsonToFile;

/**
 * Created by Galn on 05/02/2018.
 */
class CxOSAClient {

    private CxHttpClient httpClient;
    private Logger log;
    private CxScanConfig config;

    private Waiter<OSAScanStatus> osaWaiter = new Waiter<OSAScanStatus>("CxOSA scan", 20) {
        @Override
        public OSAScanStatus getStatus(String id) throws CxClientException, IOException {
            return getOSAScanStatus(id);
        }

        @Override
        public void printProgress(OSAScanStatus scanStatus) {
            printOSAProgress(scanStatus, getStartTimeSec());
        }

        @Override
        public OSAScanStatus resolveStatus(OSAScanStatus scanStatus) throws CxClientException {
            return resolveOSAStatus(scanStatus);
        }
    };

    public CxOSAClient(CxHttpClient client, Logger log, CxScanConfig config) {
        this.log = log;
        this.httpClient = client;
        this.config = config;
    }

    //API
    public String createOSAScan(long projectId) throws IOException, CxClientException {
        log.info("----------------------------------- Create CxOSA Scan:------------------------------------");
        log.info("Creating OSA scan");
        String osaDependenciesJson = config.getOsaDependenciesJson();
        if (osaDependenciesJson == null) {
            try {
                osaDependenciesJson = resolveOSADependencies();
            } catch (Exception e) {
                throw new CxClientException("Failed to resolve dependencies for OSA scan: " + e.getMessage(), e);
            }
        }
        return sendOSAScan(osaDependenciesJson, projectId);
    }

    private String resolveOSADependencies() throws JsonProcessingException {
        log.info("Scanning for CxOSA compatible files");
        Properties scannerProperties = config.getOsaFsaConfig();
        if (scannerProperties == null) {
            scannerProperties = OSAUtils.generateOSAScanConfiguration(
                    config.getOsaFolderExclusions(),
                    config.getOsaFilterPattern(),
                    config.getOsaArchiveIncludePatterns(),
                    config.getSourceDir(),
                    config.getOsaRunInstall(),
                    log);
        }
        ObjectMapper mapper = new ObjectMapper();
        log.info("Scanner properties: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(scannerProperties.toString()));
        ComponentScan componentScan = new ComponentScan(scannerProperties);
        String osaDependenciesJson = componentScan.scan();
        OSAUtils.writeToOsaListToFile(config.getReportsDir(), osaDependenciesJson, log);
        return osaDependenciesJson;
    }

    public OSAResults getOSAResults(String scanId, long projectId) throws CxClientException, InterruptedException, IOException {
        log.info("-------------------------------------Get CxOSA Results:-----------------------------------");
        log.info("Waiting for OSA scan to finish");
        OSAScanStatus osaScanStatus = osaWaiter.waitForTaskToFinish(scanId, this.config.getOsaScanTimeoutInMinutes(), log);
        log.info("OSA scan finished successfully. Retrieving OSA scan results");

        log.info("Creating OSA reports");
        OSAResults osaResults = retrieveOSAResults(scanId, osaScanStatus, projectId);

        if (config.getEnablePolicyViolations()) {
            resolveOSAViolation(osaResults, projectId);
        }

        OSAUtils.printOSAResultsToConsole(osaResults, config.getEnablePolicyViolations(), log);

        if (config.getReportsDir() != null) {
            writeJsonToFile(OSA_SUMMARY_NAME, osaResults.getResults(), config.getReportsDir(), log);
            writeJsonToFile(OSA_LIBRARIES_NAME, osaResults.getOsaLibraries(), config.getReportsDir(), log);
            writeJsonToFile(OSA_VULNERABILITIES_NAME, osaResults.getOsaVulnerabilities(), config.getReportsDir(), log);
        }

        return osaResults;
    }


    private OSAResults retrieveOSAResults(String scanId, OSAScanStatus osaScanStatus, long projectId) throws CxClientException, IOException {
        OSASummaryResults osaSummaryResults = getOSAScanSummaryResults(scanId);
        List<Library> osaLibraries = getOSALibraries(scanId);
        List<CVE> osaVulnerabilities = getOSAVulnerabilities(scanId);
        OSAResults results = new OSAResults();
        results.setOsaScanId(scanId);
        results.setResults(osaSummaryResults, osaLibraries, osaVulnerabilities, osaScanStatus, config.getUrl(), projectId);
        return results;
    }

    private void resolveOSAViolation(OSAResults osaResults, long projectId) {
        try {
            getProjectViolatedPolicies(httpClient, config.getCxARMUrl(), projectId, OPEN_SOURCE.value())
                    .forEach(osaResults::addPolicy);
        } catch (Exception ex) {
            log.error("CxARM is not available. Policy violations for OSA cannot be calculated: " + ex.getMessage());
        }
    }


    public OSAResults getLatestOSAResults(long projectId) throws CxClientException, IOException, InterruptedException {
        log.info("----------------------------------Get CxOSA Last Results:--------------------------------");
        List<OSAScanStatus> scanList = getOSALastOSAStatus(projectId);
        for (OSAScanStatus s : scanList) {
            if (Status.SUCCEEDED.value().equals(s.getState().getName())) {
                return retrieveOSAResults(s.getId(), s, projectId);
            }
        }
        return new OSAResults();
    }

    //Private Methods
    private String sendOSAScan(String osaDependenciesJson, long projectId) throws CxClientException, IOException {
        log.info("Sending OSA scan request");
        CreateOSAScanResponse osaScan = sendOSARequest(projectId, osaDependenciesJson);
        String summaryLink = OSAUtils.composeProjectOSASummaryLink(config.getUrl(), projectId);
        log.info("OSA scan created successfully. Link to project state: " + summaryLink);

        return osaScan.getScanId();
    }

    private CreateOSAScanResponse sendOSARequest(long projectId, String osaDependenciesJson) throws IOException, CxClientException {
        CreateOSAScanRequest req = new CreateOSAScanRequest(projectId, osaDependenciesJson);
        StringEntity entity = new StringEntity(convertToJson(req), StandardCharsets.UTF_8);
        return httpClient.postRequest(OSA_SCAN_PROJECT, CONTENT_TYPE_APPLICATION_JSON_V1, entity, CreateOSAScanResponse.class, 201, "create OSA scan");
    }

    private OSASummaryResults getOSAScanSummaryResults(String scanId) throws IOException, CxClientException {
        String relativePath = OSA_SCAN_SUMMARY + SCAN_ID_QUERY_PARAM + scanId;
        return httpClient.getRequest(relativePath, CONTENT_TYPE_APPLICATION_JSON_V1, OSASummaryResults.class, 200, "OSA scan summary results", false);
    }

    private List<OSAScanStatus> getOSALastOSAStatus(long projectId) throws IOException, CxClientException {
        return (List<OSAScanStatus>) httpClient.getRequest(OSA_SCANS + PROJECT_ID_QUERY_PARAM + projectId, CONTENT_TYPE_APPLICATION_JSON_V1, OSAScanStatus.class, 200, " last OSA scan ID", true);
    }

    private List<Library> getOSALibraries(String scanId) throws IOException, CxClientException {
        String relPath = OSA_SCAN_LIBRARIES + SCAN_ID_QUERY_PARAM + scanId + ITEM_PER_PAGE_QUERY_PARAM + MAX_ITEMS;
        return (List<Library>) httpClient.getRequest(relPath, CONTENT_TYPE_APPLICATION_JSON_V1, Library.class, 200, "OSA libraries", true);
    }

    private List<CVE> getOSAVulnerabilities(String scanId) throws CxClientException, IOException {
        String relPath = OSA_SCAN_VULNERABILITIES + SCAN_ID_QUERY_PARAM + scanId + ITEM_PER_PAGE_QUERY_PARAM + MAX_ITEMS;
        return (List<CVE>) httpClient.getRequest(relPath, CONTENT_TYPE_APPLICATION_JSON_V1, CVE.class, 200, "OSA vulnerabilities", true);
    }

    //Waiter - overload methods
    private OSAScanStatus getOSAScanStatus(String scanId) throws CxClientException, IOException {
        String relPath = OSA_SCAN_STATUS.replace("{scanId}", scanId);
        OSAScanStatus scanStatus = httpClient.getRequest(relPath, CONTENT_TYPE_APPLICATION_JSON_V1, OSAScanStatus.class, 200, "OSA scan status", false);
        int stateId = scanStatus.getState().getId();

        if (OSAScanStatusEnum.SUCCEEDED.getNum() == stateId) {
            scanStatus.setBaseStatus(Status.SUCCEEDED);
        } else if (OSAScanStatusEnum.IN_PROGRESS.getNum() == stateId || OSAScanStatusEnum.NOT_STARTED.getNum() == stateId) {
            scanStatus.setBaseStatus(Status.IN_PROGRESS);
        } else {
            scanStatus.setBaseStatus(Status.FAILED);
        }
        return scanStatus;
    }

    private void printOSAProgress(OSAScanStatus scanStatus, long startTime) {
        long elapsedSec = System.currentTimeMillis() / 1000 - startTime;
        long hours = elapsedSec / 3600;
        long minutes = elapsedSec % 3600 / 60;
        long seconds = elapsedSec % 60;
        String hoursStr = (hours < 10) ? ("0" + Long.toString(hours)) : (Long.toString(hours));
        String minutesStr = (minutes < 10) ? ("0" + Long.toString(minutes)) : (Long.toString(minutes));
        String secondsStr = (seconds < 10) ? ("0" + Long.toString(seconds)) : (Long.toString(seconds));
        log.info("Waiting for OSA scan results. Elapsed time: " + hoursStr + ":" + minutesStr + ":" + secondsStr + ". " +
                "Status: " + scanStatus.getState().getName());
    }

    private OSAScanStatus resolveOSAStatus(OSAScanStatus scanStatus) throws CxClientException {
        if (scanStatus == null || Status.FAILED == scanStatus.getBaseStatus()) {
            String failedMsg = scanStatus.getState() == null ? "" : "status [" + scanStatus.getState().getName() + "]. Reason: " + scanStatus.getState().getFailureReason();
            throw new CxClientException("OSA scan cannot be completed. " + failedMsg);
        }
        if (Status.SUCCEEDED == scanStatus.getBaseStatus()) {
            log.info("OSA scan finished.");
            return scanStatus;
        }
        return scanStatus;
    }
}

