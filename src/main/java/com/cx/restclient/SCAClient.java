package com.cx.restclient;

import com.cx.restclient.common.DependencyScanner;
import com.cx.restclient.common.UrlUtils;
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
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.entity.FileEntity;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * SCA - Software Composition Analysis - is the successor of OSA.
 */
public class SCAClient implements DependencyScanner {

    public static final String ENCODING = StandardCharsets.UTF_8.name();

    public static class UrlPaths {
        private UrlPaths() {
        }

        private static final String RISK_MANAGEMENT_API = "/risk-management/";
        private static final String PROJECTS = RISK_MANAGEMENT_API + "projects";
        private static final String SUMMARY_REPORT = RISK_MANAGEMENT_API + "riskReports/%s/summary";
        private static final String REPORT_ID = RISK_MANAGEMENT_API + "scans/%s/riskReportId";

        public static final String GET_UPLOAD_URL = "/api/uploads";
        public static final String CREATE_SCAN = "/api/scans";
        public static final String GET_SCAN = "/api/scans/%s";

        private static final String WEB_REPORT = "/#/projects/%s/reports/%s";
    }

    private final Logger log;
    private final CxScanConfig config;

    // This class uses its own instance of CxHttpClient, because SCA has a different base URL and Access Control server.
    private final CxHttpClient httpClient;

    private String projectId;
    private String scanId;

    SCAClient(CxScanConfig config, Logger log) {
        this.log = log;
        this.config = config;

        SCAConfig scaConfig = getScaConfig();

        httpClient = createHttpClient(scaConfig.getApiUrl());
    }

    @Override
    public void init() {
        try {
            login();
            resolveProject();
        } catch (IOException e) {
            throw new CxClientException("Failed to init CxSCA Client.", e);
        }
    }

    /**
     * Waits for SCA scan to finish, then gets scan results.
     *
     * @param target scan results will be written into this object
     *               ({@link com.cx.restclient.dto.DependencyScanResults#setScaResults}).
     * @throws CxClientException in case of a network error, scan failure or when scan is aborted by timeout.
     */
    @Override
    public void waitForScanResults(DependencyScanResults target) {
        log.info("------------------------------------Get CxSCA Results:-----------------------------------");

        log.info("Waiting for CxSCA scan to finish");
        SCAWaiter waiter = new SCAWaiter(httpClient, config);
        waiter.waitForScanToFinish(scanId);
        log.info("CxSCA scan finished successfully. Retrieving CxSCA scan results.");

        SCAResults scaResult = retrieveScanResults();
        target.setScaResults(scaResult);
    }

    @Override
    public String createScan(DependencyScanResults target) {
        log.info("----------------------------------- Creating CxSCA Scan:------------------------------------");

        scanId = null;
        try {
            SourceLocationType locationType = getScaConfig().getSourceLocationType();
            HttpResponse response;
            if (locationType == SourceLocationType.REMOTE_REPOSITORY) {
                response = submitSourcesFromRemoteRepo();
            } else {
                response = submitSourcesFromLocalDir();
            }
            scanId = extractScanIdFrom(response);
            log.info("Scan started successfully. Scan ID: {}", scanId);
        } catch (IOException e) {
            throw new CxClientException("Error creating CxSCA scan.", e);
        }

        return scanId;
    }

    private String extractScanIdFrom(HttpResponse response) {
        if (response != null && response.getLastHeader("Location") != null) {
            // Expecting a value like "/api/scans/1ecffa00-0e42-49b2-8755-388b9f6a9293"
            String urlPathWithScanId = response.getLastHeader("Location").getValue();
            String lastPathSegment = FilenameUtils.getName(urlPathWithScanId);
            if (StringUtils.isNotEmpty(lastPathSegment)) {
                return lastPathSegment;
            }
        }
        throw new CxClientException("Unable to get scan ID.");
    }

    private HttpResponse submitSourcesFromRemoteRepo() throws IOException {
        log.info("Using remote repository flow.");
        RemoteRepositoryInfo repoInfo = getScaConfig().getRemoteRepositoryInfo();
        validateRemoteRepoConfig(repoInfo);

        String repoUrl = repoInfo.getUrl().toString();
        log.info("Repository URL: {}", repoUrl);

        return sendStartScanRequest(SourceLocationType.REMOTE_REPOSITORY, repoUrl);
    }

    private HttpResponse submitSourcesFromLocalDir() throws IOException {
        log.info("Using local directory flow.");

        PathFilter filter = new PathFilter(config.getOsaFolderExclusions(), config.getOsaFilterPattern(), log);
        String sourceDir = config.getEffectiveSourceDirForDependencyScan();
        File zipFile = CxZipUtils.getZippedSources(config, filter, sourceDir, log);

        String uploadedArchiveUrl = getSourcesUploadUrl();
        uploadArchive(zipFile, uploadedArchiveUrl);
        CxZipUtils.deleteZippedSources(zipFile, config, log);

        return sendStartScanRequest(SourceLocationType.LOCAL_DIRECTORY, uploadedArchiveUrl);
    }

    private HttpResponse sendStartScanRequest(SourceLocationType sourceLocation, String sourceUrl) throws IOException {
        log.info("Sending a request to start scan.");

        ScanStartHandler handler = ScanStartHandler.builder()
                .url(sourceUrl)
                .build();

        ProjectToScan project = ProjectToScan.builder()
                .id(projectId)
                .type(sourceLocation.getApiValue())
                .handler(handler)
                .build();

        StartScanRequest request = StartScanRequest.builder()
                .project(project)
                .build();

        StringEntity entity = HttpClientHelper.convertToStringEntity(request);

        return httpClient.postRequest(UrlPaths.CREATE_SCAN, ContentType.CONTENT_TYPE_APPLICATION_JSON, entity,
                HttpResponse.class, HttpStatus.SC_CREATED, "start CxSCA scan");
    }

    private void validateRemoteRepoConfig(RemoteRepositoryInfo repoInfo) {
        if (repoInfo == null) {
            String message = String.format(
                    "%s must be provided in CxSCA configuration when using source location of type %s.",
                    RemoteRepositoryInfo.class.getName(),
                    SourceLocationType.REMOTE_REPOSITORY.name());

            throw new CxClientException(message);
        }
    }

    private String getSourcesUploadUrl() throws IOException {
        JsonNode response = httpClient.postRequest(UrlPaths.GET_UPLOAD_URL, null, null, JsonNode.class,
                HttpStatus.SC_OK, "get upload URL for sources");

        if (response == null || response.get("url") == null) {
            throw new CxClientException("Unable to get the upload URL.");
        }

        return response.get("url").asText();
    }

    private void uploadArchive(File source, String uploadUrl) throws IOException {
        log.info("Uploading the zipped sources.");

        HttpEntity request = new FileEntity(source);

        CxHttpClient client = createHttpClient(uploadUrl);

        // Relative path is empty, because we use the whole upload URL as the base URL for the HTTP client.
        // Content type is empty, because the server at uploadUrl throws an error if Content-Type is non-empty.
        client.putRequest("", "", request, JsonNode.class, HttpStatus.SC_OK, "upload ZIP file");
    }

    private void printWebReportLink(SCAResults scaResult) {
        if (!StringUtils.isEmpty(scaResult.getWebReportLink())) {
            log.info("CxSCA scan results location: {}", scaResult.getWebReportLink());
        }
    }

    @Override
    public DependencyScanResults getLatestScanResults() {
        // TODO: implement when someone actually needs this.
        return null;
    }

    void testConnection() throws IOException {
        // The calls below allow to check both access control and API connectivity.
        login();
        getProjects();
    }

    private void login() throws IOException {
        log.info("Logging into CxSCA.");
        SCAConfig scaConfig = getScaConfig();

        LoginSettings settings = new LoginSettings();
        settings.setAccessControlBaseUrl(scaConfig.getAccessControlUrl());
        settings.setUsername(scaConfig.getUsername());
        settings.setPassword(scaConfig.getPassword());
        settings.setTenant(scaConfig.getTenant());
        settings.setClientTypeForPasswordAuth(ClientType.SCA_CLI);

        httpClient.login(settings);
    }

    private void resolveProject() throws IOException {
        String projectName = config.getProjectName();
        log.info("Getting project by name: '{}'", projectName);
        projectId = getProjectIdByName(projectName);
        if (projectId == null) {
            log.info("Project not found, creating a new one.");
            projectId = createProject(projectName);
            log.info("Created a project with ID {}", projectId);
        }
        else {
            log.info("Project already exists with ID {}", projectId);
        }
    }

    private String getProjectIdByName(String name) throws IOException {
        if (StringUtils.isEmpty(name)) {
            throw new CxClientException("Non-empty project name must be provided.");
        }

        List<Project> allProjects = getProjects();

        return allProjects.stream()
                .filter((Project project) -> name.equals(project.getName()))
                .map(Project::getId)
                .findFirst()
                .orElse(null);
    }

    private List<Project> getProjects() throws IOException {
        return (List<Project>) httpClient.getRequest(UrlPaths.PROJECTS, ContentType.CONTENT_TYPE_APPLICATION_JSON,
                Project.class, HttpStatus.SC_OK, "CxSCA projects", true);
    }

    private String createProject(String name) throws IOException {
        CreateProjectRequest request = new CreateProjectRequest();
        request.setName(name);

        StringEntity entity = HttpClientHelper.convertToStringEntity(request);

        Project newProject = httpClient.postRequest(UrlPaths.PROJECTS,
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                entity,
                Project.class,
                HttpStatus.SC_CREATED,
                "create a project");

        return newProject.getId();
    }

    private SCAResults retrieveScanResults() {
        try {
            String reportId = getReportId();

            SCAResults result = new SCAResults();
            result.setScanId(scanId);

            SCASummaryResults scanSummary = getSummaryReport(reportId);
            result.setSummary(scanSummary);
            printSummary(scanSummary);

            String reportLink = getWebReportLink(reportId);
            result.setWebReportLink(reportLink);
            printWebReportLink(result);
            return result;
        } catch (IOException e) {
            throw new CxClientException("Error retrieving CxSCA scan results.", e);
        }
    }

    private String getWebReportLink(String reportId) {
        final String MESSAGE = "Unable to generate web report link.";
        String result = null;
        try {
            String webAppUrl = getScaConfig().getWebAppUrl();
            if (StringUtils.isEmpty(webAppUrl)) {
                log.warn("{} Web app URL is not specified.", MESSAGE);
            } else {
                String path = String.format(UrlPaths.WEB_REPORT,
                        URLEncoder.encode(projectId, ENCODING),
                        URLEncoder.encode(reportId, ENCODING));

                result = UrlUtils.parseURLToString(webAppUrl, path);
            }
        } catch (MalformedURLException e) {
            log.warn("Unable to generate web report link: invalid web app URL.", e);
        } catch (Exception e) {
            log.warn("Unable to generate web report link: general error.", e);
        }
        return result;
    }

    private String getReportId() throws IOException {
        log.debug("Getting report ID by scan ID: {}", scanId);
        String path = String.format(UrlPaths.REPORT_ID,
                URLEncoder.encode(scanId, ENCODING));

        String reportId = httpClient.getRequest(path,
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                String.class,
                HttpStatus.SC_OK,
                "Risk report ID",
                false);
        log.debug("Found report ID: {}", reportId);
        return reportId;
    }

    private SCASummaryResults getSummaryReport(String reportId) throws IOException {
        log.debug("Getting summary report.");

        String path = String.format(UrlPaths.SUMMARY_REPORT,
                URLEncoder.encode(reportId, ENCODING));

        return httpClient.getRequest(path,
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                SCASummaryResults.class,
                HttpStatus.SC_OK,
                "CxSCA report summary",
                false);
    }

    private void printSummary(SCASummaryResults summary) {
        if (log.isInfoEnabled()) {
            log.info("\n----CxSCA risk report summary----");
            log.info("Created on: {}", summary.getCreatedOn());
            log.info("Direct packages: {}", summary.getDirectPackages());
            log.info("High vulnerabilities: {}", summary.getHighVulnerabilityCount());
            log.info("Medium vulnerabilities: {}", summary.getMediumVulnerabilityCount());
            log.info("Low vulnerabilities: {}", summary.getLowVulnerabilityCount());
            log.info("Risk report ID: {}", summary.getRiskReportId());
            log.info("Risk score: {}", summary.getRiskScore());
            log.info("Total packages: {}", summary.getTotalPackages());
            log.info(String.format("Total outdated packages: %d%n", summary.getTotalOutdatedPackages()));
        }
    }

    private SCAConfig getScaConfig() {
        SCAConfig result = config.getScaConfig();
        if (result == null) {
            throw new CxClientException("CxSCA scan configuration is missing.");
        }
        return result;
    }

    private CxHttpClient createHttpClient(String baseUrl) {
        return new CxHttpClient(baseUrl,
                config.getCxOrigin(),
                config.isDisableCertificateValidation(),
                config.isUseSSOLogin(),
                null,
                config.getProxyConfig(),
                log);
    }
}
