package com.cx.restclient;

import com.cx.restclient.common.DependencyScanner;
import com.cx.restclient.common.UrlUtils;
import com.cx.restclient.common.Waiter;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.DependencyScanResults;
import com.cx.restclient.dto.LoginSettings;
import com.cx.restclient.dto.PathFilter;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.httpClient.CxHttpClient;
import com.cx.restclient.httpClient.utils.ContentType;
import com.cx.restclient.httpClient.utils.HttpClientHelper;
import com.cx.restclient.osa.dto.ClientType;
import com.cx.restclient.sast.utils.zip.CxZipUtils;
import com.cx.restclient.sca.SCAWaiter;
import com.cx.restclient.sca.dto.*;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.ContentBody;
import org.apache.http.entity.mime.content.InputStreamBody;
import org.apache.http.entity.mime.content.StringBody;
import org.slf4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.util.List;

/**
 * SCA - Software Composition Analysis - is the successor of OSA.
 */
class SCAClient implements DependencyScanner {
    private static final String API_PATH = "api/";

    private final Logger log;
    private final CxScanConfig config;

    // This class uses its own instance of CxHttpClient, because SCA has a different base URL and Access Control server.
    private final CxHttpClient httpClient;

    private String projectId;
    private final Waiter<ScanStatusResponse> waiter;
    private String scanId;

    SCAClient(Logger log, CxScanConfig config) throws MalformedURLException {
        this.log = log;
        this.config = config;

        int pollInterval = config.getOsaProgressInterval() != null ? config.getOsaProgressInterval() : 20;
        int marRetries = config.getConnectionRetries() != null ? config.getConnectionRetries() : 3;

        SCAConfig scaConfig = config.getScaConfig();
        String apiBaseUrl = UrlUtils.parseURLToString(scaConfig.getApiUrl(), API_PATH);

        httpClient = new CxHttpClient(apiBaseUrl,
                config.getCxOrigin(),
                config.isDisableCertificateValidation(),
                config.isUseSSOLogin(),
                log);

        waiter = new SCAWaiter("SCA scan", pollInterval, marRetries, httpClient, log);
    }

    @Override
    public void init() throws CxClientException {
        try {
            login();
            resolveProject();
        } catch (IOException e) {
            throw new CxClientException("Failed to init SCA Client.", e);
        }
    }

    @Override
    public String createScan(DependencyScanResults target) throws CxClientException {
        log.info("----------------------------------- Create SCA Scan:------------------------------------");
        log.info("Creating SCA scan");

        PathFilter filter = new PathFilter(config.getOsaFolderExclusions(), config.getOsaFilterPattern(), log);
        scanId = null;
        try {
            File zipFile = CxZipUtils.getZippedSources(config, filter, log);
            scanId = uploadZipFile(zipFile);
            CxZipUtils.deleteZippedSources(zipFile, config, log);
        } catch (IOException e) {
            throw new CxClientException("Error creating SCA scan.", e);
        }

        return scanId;
    }

    @Override
    public void waitForScanResults(DependencyScanResults target) throws CxClientException {
        log.info("------------------------------------Get SCA Results:-----------------------------------");

        log.info("Waiting for SCA scan to finish");
        waiter.waitForTaskToFinish(scanId, this.config.getOsaScanTimeoutInMinutes(), log);

        log.info("SCA scan finished successfully. Retrieving SCA scan results.");
        SCAResults scaResult;
        try {
            scaResult = retrieveScanResults();
        } catch (IOException e) {
            throw new CxClientException("Error retrieving SCA scan results.", e);
        }

        target.setScaResults(scaResult);
    }

    @Override
    public DependencyScanResults getLatestScanResults() {
        // TODO
        return null;
    }

    private void login() throws IOException, CxClientException {
        log.info("Logging into SCA.");
        SCAConfig scaConfig = config.getScaConfig();

        LoginSettings settings = new LoginSettings();
        settings.setAccessControlBaseUrl(scaConfig.getAccessControlUrl());
        settings.setUsername(scaConfig.getUsername());
        settings.setPassword(scaConfig.getPassword());
        settings.setTenant(scaConfig.getTenant());
        settings.setClientTypeForPasswordAuth(ClientType.SCA_CLI);

        httpClient.login(settings);
    }

    private void resolveProject() throws IOException, CxClientException {
        String projectName = config.getScaConfig().getProjectName();
        projectId = getProjectIdByName(projectName);
        if (projectId == null) {
            log.debug("Project not found, creating a new one.");
            projectId = createProject(projectName);
        }
        log.debug("Using project ID: " + projectId);
    }

    private String getProjectIdByName(String name) throws IOException, CxClientException {
        log.debug("Getting project by name: " + name);

        List<Project> allProjects = (List<Project>) httpClient.getRequest("projects",
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                Project.class,
                HttpStatus.SC_OK,
                "SCA projects",
                true);

        String result = allProjects.stream()
                .filter((Project project) -> name.equals(project.getName()))
                .map(project -> project.getId())
                .findFirst()
                .orElse(null);

        return result;
    }

    private String createProject(String name) throws CxClientException, IOException {
        CreateProjectRequest request = new CreateProjectRequest();
        request.setName(name);

        StringEntity entity = HttpClientHelper.convertToStringEntity(request);

        Project newProject = httpClient.postRequest("projects",
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                entity,
                Project.class,
                HttpStatus.SC_CREATED,
                "create a project");

        return newProject.getId();
    }

    private String uploadZipFile(File zipFile) throws IOException, CxClientException {
        log.info("Uploading zipped sources.");

        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
        builder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);

        InputStream input = new FileInputStream(zipFile.getAbsoluteFile());
        InputStreamBody fileBody = new InputStreamBody(input, org.apache.http.entity.ContentType.APPLICATION_OCTET_STREAM, "zippedSource");
        builder.addPart("zipFile", fileBody);

        ContentBody projectIdBody = new StringBody(projectId, org.apache.http.entity.ContentType.APPLICATION_FORM_URLENCODED);
        builder.addPart("projectId", projectIdBody);

        HttpEntity entity = builder.build();

        String scanId = httpClient.postRequest("scans/zip", null, entity, String.class, HttpStatus.SC_OK, "upload ZIP file");
        log.debug("Scan ID: " + scanId);

        return scanId;
    }

    private SCAResults retrieveScanResults() throws IOException, CxClientException {
        String reportId = getReportId();
        SCASummaryResults scanSummary = getSummaryReport(reportId);

        SCAResults result = new SCAResults();
        result.setScanId(scanId);
        result.setSummary(scanSummary);
        return result;
    }

    private String getReportId() throws IOException, CxClientException {
        log.debug("Getting report ID by scan ID: " + scanId);
        String path = String.format("scans/%s/riskReportId", scanId);
        String reportId = httpClient.getRequest(path,
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                String.class,
                HttpStatus.SC_OK,
                "Risk report ID",
                false);
        log.debug("Found report ID: " + reportId);
        return reportId;
    }

    private SCASummaryResults getSummaryReport(String reportId) throws IOException, CxClientException {
        log.debug("Getting summary report.");

        String path = String.format("riskReports/%s/summary", reportId);

        SCASummaryResults result = httpClient.getRequest(path,
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                SCASummaryResults.class,
                HttpStatus.SC_OK,
                "SCA report summary",
                false);

        return result;
    }
}
