package com.cx.restclient;

import com.cx.restclient.common.Waiter;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.RemoteSourceRequest;
import com.cx.restclient.dto.RemoteSourceTypes;
import com.cx.restclient.dto.Status;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.httpClient.CxHttpClient;
import com.cx.restclient.sast.dto.*;
import com.cx.restclient.sast.utils.SASTUtils;
import com.cx.restclient.sast.utils.zip.CxZipUtils;
import com.google.gson.Gson;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.json.JSONObject;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.cx.restclient.cxArm.dto.CxProviders.SAST;
import static com.cx.restclient.cxArm.utils.CxARMUtils.getProjectViolatedPolicies;
import static com.cx.restclient.httpClient.utils.ContentType.*;
import static com.cx.restclient.httpClient.utils.HttpClientHelper.convertToJson;
import static com.cx.restclient.sast.utils.SASTParam.*;
import static com.cx.restclient.sast.utils.SASTUtils.*;


/**
 * Created by Galn on 05/02/2018.
 */
class CxSASTClient {

    public static final String JENKINS = "jenkins";
    private Logger log;
    private CxHttpClient httpClient;
    private CxScanConfig config;
    private int reportTimeoutSec = 5000;
    private int cxARMTimeoutSec = 1000;

    private Waiter<ResponseQueueScanStatus> sastWaiter = new Waiter<ResponseQueueScanStatus>("CxSAST scan", 20) {
        @Override
        public ResponseQueueScanStatus getStatus(String id) throws CxClientException, IOException {
            return getSASTScanStatus(id);
        }

        @Override
        public void printProgress(ResponseQueueScanStatus scanStatus) {
            printSASTProgress(scanStatus, getStartTimeSec());
        }

        @Override
        public ResponseQueueScanStatus resolveStatus(ResponseQueueScanStatus scanStatus) throws CxClientException {
            return resolveSASTStatus(scanStatus);
        }
    };

    private Waiter<ReportStatus> reportWaiter = new Waiter<ReportStatus>("Scan report", 10) {
        @Override
        public ReportStatus getStatus(String id) throws CxClientException, IOException {
            return getReportStatus(id);
        }

        @Override
        public void printProgress(ReportStatus reportStatus) {
            printReportProgress(reportStatus, getStartTimeSec());
        }

        @Override
        public ReportStatus resolveStatus(ReportStatus reportStatus) throws CxClientException {
            return resolveReportStatus(reportStatus);
        }
    };

    private Waiter<CxARMStatus> cxARMWaiter = new Waiter<CxARMStatus>("CxARM policy violations", 20) {
        @Override
        public CxARMStatus getStatus(String id) throws CxClientException, IOException {
            return getCxARMStatus(id);
        }

        @Override
        public void printProgress(CxARMStatus cxARMStatus) {
            printCxARMProgress(cxARMStatus, getStartTimeSec());
        }

        @Override
        public CxARMStatus resolveStatus(CxARMStatus cxARMStatus) throws CxClientException {
            return resolveCxARMStatus(cxARMStatus);
        }
    };

    CxSASTClient(CxHttpClient client, Logger log, CxScanConfig config) {
        this.log = log;
        this.httpClient = client;
        this.config = config;
    }

    //**------ API  ------**//

    //CREATE SAST scan
    long createSASTScan(long projectId) throws IOException, CxClientException {
        log.info("-----------------------------------Create CxSAST Scan:------------------------------------");
        if (config.isAvoidDuplicateProjectScans() != null && config.isAvoidDuplicateProjectScans() && projectHasQueuedScans(projectId)) {
            throw new CxClientException("\nAvoid duplicate project scans in queue\n");
        }
        if (config.getRemoteType() == null) { //scan is local
            return createLocalSASTScan(projectId);
        } else {
            return createRemoteSourceScan(projectId);
        }
    }

    private long createLocalSASTScan(long projectId) throws IOException, CxClientException {

        ScanSettingResponse scanSettingResponse = getScanSetting(projectId);
        ScanSettingRequest scanSettingRequest = new ScanSettingRequest();
        scanSettingRequest.setEngineConfigurationId(scanSettingResponse.getEngineConfiguration().getId());//todo check for null
        scanSettingRequest.setProjectId(projectId);
        scanSettingRequest.setPresetId(config.getPresetId());
        if (config.getEngineConfigurationId() != null) {
            scanSettingRequest.setEngineConfigurationId(config.getEngineConfigurationId());
        }
        //Define createSASTScan settings
        defineScanSetting(scanSettingRequest);

        //prepare sources for scan
        if (config.getZipFile() == null) {
            log.info("Zipping sources");
            File zipTempFile = CxZipUtils.zipWorkspaceFolder(config, MAX_ZIP_SIZE_BYTES, log);
            //Upload zipped source file
            uploadZipFile(zipTempFile, projectId);
            deleteTempZipFile(zipTempFile, log);
        } else {
            uploadZipFile(config.getZipFile(), projectId);
        }

        //Start a new createSASTScan
        log.info("Uploading zip file");
        CreateScanRequest scanRequest = new CreateScanRequest(projectId, config.getIncremental(), config.getPublic(), config.getForceScan(), config.getScanComment() == null ? "" : config.getScanComment());
        log.info("Sending SAST scan request");
        CxID createScanResponse = createScan(scanRequest);
        log.info(String.format("SAST Scan created successfully. Link to project state: " + config.getUrl() + LINK_FORMAT, projectId));

        return createScanResponse.getId();
    }

    private long createRemoteSourceScan(long projectId) throws IOException, CxClientException {
        HttpEntity entity;
        RemoteSourceRequest req = new RemoteSourceRequest(config);
        RemoteSourceTypes type = req.getType();

        switch (type) {
            case SVN:
            case TFS:
                MultipartEntityBuilder builder = MultipartEntityBuilder.create();
                builder.addBinaryBody("privateKey", req.getPrivateKey(), ContentType.APPLICATION_JSON, null);
                builder.addTextBody("absoluteUrl", req.getUrl(), ContentType.APPLICATION_JSON);
                builder.addTextBody("port", String.valueOf(req.getPort()), ContentType.APPLICATION_JSON);
                builder.addTextBody("paths", StringUtils.join(req.getPaths(), ";"), ContentType.APPLICATION_JSON);
                entity = builder.build();
                break;
            case PERFORCE:
                if (config.getPreforceMode() != null) {
                    req.setBrowseMode("Workspace");
                } else {
                    req.setBrowseMode("Depot");
                }
                entity = new StringEntity(convertToJson(req), StandardCharsets.UTF_8);
                break;
            case SHARED:
                entity = new StringEntity(new Gson().toJson(req), StandardCharsets.UTF_8);
                break;
            case GIT:
                if (req.getPrivateKey().length < 1) {
                    Map<String, String> content = new HashMap<>();
                    content.put("url", config.getRemoteSrcUrl());
                    content.put("branch", config.getRemoteSrcBranch());
                    entity = new StringEntity(new JSONObject(content).toString(), StandardCharsets.UTF_8);
                } else {
                    builder = MultipartEntityBuilder.create();
                    builder.addTextBody("url", req.getUrl(), ContentType.APPLICATION_JSON);
                    builder.addTextBody("branch", config.getRemoteSrcBranch(), ContentType.APPLICATION_JSON); //todo add branch to req OR using without this else??
                    builder.addBinaryBody("privateKey", req.getPrivateKey(), ContentType.MULTIPART_FORM_DATA, null);
                    entity = builder.build();
                }
                break;
            default:
                log.error("todo");
                entity = new StringEntity("", StandardCharsets.UTF_8);

        }
        return createRemoteSourceScan(projectId, entity, type.value()).getId();
    }


    //GET SAST results + reports
    public SASTResults waitForSASTResults(long scanId, long projectId) throws InterruptedException, IOException, CxClientException {
        SASTResults sastResults;

        log.info("------------------------------------Get CxSAST Results:-----------------------------------");
        //wait for SAST scan to finish
        log.info("Waiting for CxSAST scan to finish.");
        sastWaiter.waitForTaskToFinish(Long.toString(scanId), config.getSastScanTimeoutInMinutes() * 60, log);
        log.info("Retrieving SAST scan results");

        //retrieve SAST scan results
        sastResults = retrieveSASTResults(scanId, projectId);
        if (config.getEnablePolicyViolations()) {
            resolveSASTViolation(sastResults, projectId);
        }
        SASTUtils.printSASTResultsToConsole(sastResults, config.getEnablePolicyViolations(), log);

        //PDF report
        if (config.getGeneratePDFReport()) {
            log.info("Generating PDF report");
            byte[] pdfReport = getScanReport(sastResults.getScanId(), ReportType.PDF, CONTENT_TYPE_APPLICATION_PDF_V1);
            sastResults.setPDFReport(pdfReport);
            if (config.getReportsDir() != null) {
                String now = new SimpleDateFormat("dd_MM_yyyy-HH_mm_ss").format(new Date());
                String pdfFileName = PDF_REPORT_NAME + "_" + now + ".pdf";
                pdfFileName = writePDFReport(pdfReport, config.getReportsDir(), pdfFileName, log);
                sastResults.setPdfFileName(pdfFileName);
            }
        }
        return sastResults;
    }

    private void resolveSASTViolation(SASTResults sastResults, long projectId) {
        try {
            cxARMWaiter.waitForTaskToFinish(Long.toString(projectId), cxARMTimeoutSec, log);
            getProjectViolatedPolicies(httpClient, config.getCxARMUrl(), projectId, SAST.value())
                    .forEach(sastResults::addPolicy);
        } catch (Exception ex) {
            log.error("CxARM is not available. Policy violations for SAST cannot be calculated: " + ex.getMessage());
        }
    }

    private SASTResults retrieveSASTResults(long scanId, long projectId) throws CxClientException, IOException, InterruptedException {
        SASTResults sastResults = new SASTResults();
        SASTStatisticsResponse statisticsResults = getScanStatistics(scanId);
        sastResults.setResults(scanId, statisticsResults, config.getUrl(), projectId);

        //SAST detailed report
        if (config.getGenerateXmlReport() == null || config.getGenerateXmlReport()) {
            byte[] cxReport = getScanReport(sastResults.getScanId(), ReportType.XML, CONTENT_TYPE_APPLICATION_XML_V1);
            CxXMLResults reportObj = convertToXMLResult(cxReport);
            sastResults.setScanDetailedReport(reportObj);
            sastResults.setRawXMLReport(cxReport);
        }
        sastResults.setSastResultsReady(true);
        return sastResults;
    }

    SASTResults getLatestSASTResults(long projectId) throws IOException, CxClientException, InterruptedException {
        log.info("---------------------------------Get Last CxSAST Results:--------------------------------");
        List<LastScanResponse> scanList = getLatestSASTStatus(projectId);
        for (LastScanResponse s : scanList) {
            if (CurrentStatus.FINISHED.value().equals(s.getStatus().getName())) {
                return retrieveSASTResults(s.getId(), projectId);
            }
        }
        return new SASTResults();
    }

    //Cancel SAST Scan
    public void cancelSASTScan(long scanId) throws IOException, CxClientException {
        UpdateScanStatusRequest request = new UpdateScanStatusRequest(CurrentStatus.CANCELED);
        String json = convertToJson(request);
        StringEntity entity = new StringEntity(json, StandardCharsets.UTF_8);
        httpClient.patchRequest(SAST_QUEUE_SCAN_STATUS.replace("{scanId}", Long.toString(scanId)), CONTENT_TYPE_APPLICATION_JSON_V1, entity, 200, "cancel SAST scan");
        log.info("SAST Scan canceled. (scanId: " + scanId + ")");
    }

    //**------ Private Methods  ------**//
    private boolean projectHasQueuedScans(long projectId) throws IOException, CxClientException {
        List<ResponseQueueScanStatus> queuedScans = getQueueScans(projectId);
        for (ResponseQueueScanStatus scan : queuedScans) {
            if (isStatusToAvoid(scan.getStage().getValue()) && scan.getProject().getId() == projectId) {
                return true;
            }
        }
        return false;
    }

    private boolean isStatusToAvoid(String status) {
        QueueStatus qStatus = QueueStatus.valueOf(status);

        switch (qStatus) {
            case New:
            case PreScan:
            case SourcePullingAndDeployment:
            case Queued:
            case Scanning:
            case PostScan:
                return true;
        }
        return false;
    }

    private ScanSettingResponse getScanSetting(long projectId) throws IOException, CxClientException {
        return httpClient.getRequest(SAST_GET_SCAN_SETTINGS.replace("{projectId}", Long.toString(projectId)), CONTENT_TYPE_APPLICATION_JSON_V1, ScanSettingResponse.class, 200, "Scan setting", false);
    }

    private void defineScanSetting(ScanSettingRequest scanSetting) throws IOException, CxClientException {
        StringEntity entity = new StringEntity(convertToJson(scanSetting), StandardCharsets.UTF_8);
        httpClient.putRequest(SAST_UPDATE_SCAN_SETTINGS, CONTENT_TYPE_APPLICATION_JSON_V1, entity, CxID.class, 200, "define scan setting");
    }

    private void uploadZipFile(File zipFile, long projectId) throws CxClientException, IOException {
        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
        builder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
        builder.addBinaryBody("zippedSource", zipFile);
        HttpEntity entity = builder.build();
        httpClient.postRequest(SAST_ZIP_ATTACHMENTS.replace("{projectId}", Long.toString(projectId)), null, entity, null, 204, "upload ZIP file");
    }

    private CxID createScan(CreateScanRequest request) throws CxClientException, IOException {
        StringEntity entity = new StringEntity(convertToJson(request), StandardCharsets.UTF_8);
        return httpClient.postRequest(SAST_CREATE_SCAN, CONTENT_TYPE_APPLICATION_JSON_V1, entity, CxID.class, 201, "create new SAST Scan");
    }

    private CxID createRemoteSourceScan(long projectId, HttpEntity entity, String sourceType) throws IOException, CxClientException {
        return httpClient.postRequest(SAST_CREATE_REMOTE_SOURCE_SCAN.replace("{projectId}", Long.toString(projectId)).replace("{sourceType}", sourceType), CONTENT_TYPE_APPLICATION_JSON_V1, entity, CxID.class, 204, "create " + sourceType + " remote source scan setting");
    }

    private SASTStatisticsResponse getScanStatistics(long scanId) throws CxClientException, IOException {
        return httpClient.getRequest(SAST_SCAN_RESULTS_STATISTICS.replace("{scanId}", Long.toString(scanId)), CONTENT_TYPE_APPLICATION_JSON_V1, SASTStatisticsResponse.class, 200, "SAST scan statistics", false);
    }

    private List<LastScanResponse> getLatestSASTStatus(long projectId) throws CxClientException, IOException {
        return (List<LastScanResponse>) httpClient.getRequest(SAST_GET_PROJECT_SCANS.replace("{projectId}", Long.toString(projectId)), CONTENT_TYPE_APPLICATION_JSON_V1, LastScanResponse.class, 200, "last SAST scan ID", true);
    }

    private List<ResponseQueueScanStatus> getQueueScans(long projectId) throws IOException, CxClientException {
        return (List<ResponseQueueScanStatus>) httpClient.getRequest(SAST_GET_QUEUED_SCANS.replace("{projectId}", Long.toString(projectId)), CONTENT_TYPE_APPLICATION_JSON_V1, ResponseQueueScanStatus.class, 200, "scans in the queue. (projectId: )" + projectId, true);
    }

    private CreateReportResponse createScanReport(CreateReportRequest reportRequest) throws CxClientException, IOException {
        StringEntity entity = new StringEntity(convertToJson(reportRequest), StandardCharsets.UTF_8);
        return httpClient.postRequest(SAST_CREATE_REPORT, CONTENT_TYPE_APPLICATION_JSON_V1, entity, CreateReportResponse.class, 202, "to create " + reportRequest.getReportType() + " scan report");
    }

    private byte[] getScanReport(long scanId, ReportType reportType, String contentType) throws CxClientException, IOException, InterruptedException {
        CreateReportRequest reportRequest = new CreateReportRequest(scanId, reportType.name());
        CreateReportResponse createReportResponse = createScanReport(reportRequest);
        int reportId = createReportResponse.getReportId();
        reportWaiter.waitForTaskToFinish(Long.toString(reportId), reportTimeoutSec, log);

        return getReport(reportId, contentType);
    }

    private byte[] getReport(long reportId, String contentType) throws CxClientException, IOException {
        return httpClient.getRequest(SAST_GET_REPORT.replace("{reportId}", Long.toString(reportId)), contentType, byte[].class, 200, " scan report: " + reportId, false);
    }

    //SCAN Waiter - overload methods
    private ResponseQueueScanStatus getSASTScanStatus(String scanId) throws CxClientException, IOException {
        ResponseQueueScanStatus scanStatus = httpClient.getRequest(SAST_QUEUE_SCAN_STATUS.replace("{scanId}", scanId), CONTENT_TYPE_APPLICATION_JSON_V1, ResponseQueueScanStatus.class, 200, "SAST scan status", false);
        String currentStatus = scanStatus.getStage().getValue();

        if (CurrentStatus.FAILED.value().equals(currentStatus) || CurrentStatus.CANCELED.value().equals(currentStatus) ||
                CurrentStatus.DELETED.value().equals(currentStatus) || CurrentStatus.UNKNOWN.value().equals(currentStatus)) {
            scanStatus.setBaseStatus(Status.FAILED);
        } else if (CurrentStatus.FINISHED.value().equals(currentStatus)) {
            scanStatus.setBaseStatus(Status.SUCCEEDED);
        } else {
            scanStatus.setBaseStatus(Status.IN_PROGRESS);
        }

        return scanStatus;
    }

    private void printSASTProgress(ResponseQueueScanStatus scanStatus, long startTime) {
        long elapsedSec = System.currentTimeMillis() / 1000 - startTime;
        long hours = elapsedSec / 3600;
        long minutes = elapsedSec % 3600 / 60;
        long seconds = elapsedSec % 60;
        String hoursStr = (hours < 10) ? ("0" + Long.toString(hours)) : (Long.toString(hours));
        String minutesStr = (minutes < 10) ? ("0" + Long.toString(minutes)) : (Long.toString(minutes));
        String secondsStr = (seconds < 10) ? ("0" + Long.toString(seconds)) : (Long.toString(seconds));

        String prefix = (scanStatus.getTotalPercent() < 10) ? " " : "";
        log.info("Waiting for SAST scan results. Elapsed time: " + hoursStr + ":" + minutesStr + ":" + secondsStr + ". " + prefix +
                scanStatus.getTotalPercent() + "% processed. Status: " + scanStatus.getStage().getValue() + ".");
    }

    private ResponseQueueScanStatus resolveSASTStatus(ResponseQueueScanStatus scanStatus) throws CxClientException {
        if (scanStatus != null && Status.SUCCEEDED == scanStatus.getBaseStatus()) {
            log.info("SAST scan finished successfully.");
            return scanStatus;
        } else {
            throw new CxClientException("SAST scan cannot be completed. status [" + scanStatus.getStage().getValue() + "]: " + scanStatus.getStageDetails());
        }
    }

    //Report Waiter - overload methods
    private ReportStatus getReportStatus(String reportId) throws CxClientException, IOException {
        ReportStatus reportStatus = httpClient.getRequest(SAST_GET_REPORT_STATUS.replace("{reportId}", reportId), CONTENT_TYPE_APPLICATION_JSON_V1, ReportStatus.class, 200, " report status", false);
        reportStatus.setBaseId(reportId);
        String currentStatus = reportStatus.getStatus().getValue();
        if (currentStatus.equals(ReportStatusEnum.INPROCESS.value())) {
            reportStatus.setBaseStatus(Status.IN_PROGRESS);
        } else if (currentStatus.equals(ReportStatusEnum.FAILED.value())) {
            reportStatus.setBaseStatus(Status.FAILED);
        } else {
            reportStatus.setBaseStatus(Status.SUCCEEDED); //todo fix it!!
        }

        return reportStatus;
    }

    private void printReportProgress(ReportStatus reportStatus, long startTime) {
        String reportType = reportStatus.getContentType().replace("application/", "");
        log.info("Waiting for server to generate " + reportType + " report. " + (startTime + reportTimeoutSec - (System.currentTimeMillis() / 1000)) + " seconds left to timeout");
    }

    private ReportStatus resolveReportStatus(ReportStatus reportStatus) throws CxClientException {
        if (reportStatus != null && Status.SUCCEEDED == reportStatus.getBaseStatus()) {
            return reportStatus;
        } else {
            throw new CxClientException("Generation of scan report [id=" + reportStatus.getBaseId() + "] failed.");
        }
    }


    //CxARM Waiter - overload methods
    private CxARMStatus getCxARMStatus(String projectId) throws CxClientException, IOException {
        CxARMStatus cxARMStatus = httpClient.getRequest(SAST_GET_CXARM_STATUS.replace("{projectId}", projectId), CONTENT_TYPE_APPLICATION_JSON_V1, CxARMStatus.class, 200, " cxARM status", false);
        cxARMStatus.setBaseId(projectId);

        String currentStatus = cxARMStatus.getStatus();
        if (currentStatus.equals(CxARMStatusEnum.IN_PROGRESS.value())) {
            cxARMStatus.setBaseStatus(Status.IN_PROGRESS);
        } else if (currentStatus.equals(CxARMStatusEnum.FAILED.value())) {
            cxARMStatus.setBaseStatus(Status.FAILED);
        } else if (currentStatus.equals(CxARMStatusEnum.FINISHED.value())) {
            cxARMStatus.setBaseStatus(Status.SUCCEEDED);
        } else {
            cxARMStatus.setBaseStatus(Status.FAILED);
        }

        return cxARMStatus;
    }

    private void printCxARMProgress(CxARMStatus cxARMStatus, long startTime) {
        log.info("Waiting for server to retrieve policy violations. " + (startTime + cxARMTimeoutSec - (System.currentTimeMillis() / 1000)) + " seconds left to timeout"); //todo Liran
    }

    private CxARMStatus resolveCxARMStatus(CxARMStatus cxARMStatus) throws CxClientException {
        if (cxARMStatus != null && Status.SUCCEEDED == cxARMStatus.getBaseStatus()) {
            return cxARMStatus;
        } else {
            throw new CxClientException("Getting policy violations of project [id=" + cxARMStatus.getBaseId() + "] failed."); //todo Liran
        }
    }

}
