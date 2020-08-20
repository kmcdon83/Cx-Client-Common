package com.cx.restclient.ast;

import com.cx.restclient.ast.dto.common.*;
import com.cx.restclient.ast.dto.sca.*;
import com.cx.restclient.ast.dto.sca.report.Package;
import com.cx.restclient.ast.dto.sca.report.*;
import com.cx.restclient.common.Scanner;
import com.cx.restclient.common.UrlUtils;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.*;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.exception.CxHTTPClientException;
import com.cx.restclient.httpClient.CxHttpClient;
import com.cx.restclient.httpClient.utils.ContentType;
import com.cx.restclient.httpClient.utils.HttpClientHelper;
import com.cx.restclient.osa.dto.ClientType;
import com.cx.restclient.sast.utils.zip.*;
import com.cx.restclient.sca.dto.CxSCAResolvingConfiguration;
import com.cx.restclient.sca.utils.CxSCAFileSystemUtils;
import com.cx.restclient.sca.utils.fingerprints.CxSCAScanFingerprints;
import com.cx.restclient.sca.utils.fingerprints.FingerprintCollector;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.*;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.FileEntity;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.stream.Collectors;

import static com.cx.restclient.sast.utils.SASTParam.MAX_ZIP_SIZE_BYTES;
import static com.cx.restclient.sast.utils.SASTParam.TEMP_FILE_NAME_TO_ZIP;

/**
 * SCA - Software Composition Analysis - is the successor of OSA.
 */
public class AstScaClient extends AstClient implements Scanner {
    private static class UrlPaths {
        private static final String RISK_MANAGEMENT_API = "/risk-management/";
        public static final String PROJECTS = RISK_MANAGEMENT_API + "projects";
        public static final String SUMMARY_REPORT = RISK_MANAGEMENT_API + "riskReports/%s/summary";
        public static final String FINDINGS = RISK_MANAGEMENT_API + "riskReports/%s/vulnerabilities";
        public static final String PACKAGES = RISK_MANAGEMENT_API + "riskReports/%s/packages";
        public static final String LATEST_SCAN = RISK_MANAGEMENT_API + "riskReports?size=1&projectId=%s";
        public static final String GET_UPLOAD_URL = "/api/uploads";
        public static final String WEB_REPORT = "/#/projects/%s/reports/%s";
        public static final String RESOLVING_CONFIGURATION_API = "/settings/projects/%s/resolving-configuration";
    }

    private static final String ENGINE_TYPE_FOR_API = "sca";

    public static final String ENCODING = StandardCharsets.UTF_8.name();

    private static final String TENANT_HEADER_NAME = "Account-Name";

    private static final ObjectMapper caseInsensitiveObjectMapper = new ObjectMapper()
            // Ignore any fields that can be added to SCA API in the future.
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            // We need this feature to properly deserialize finding severity,
            // e.g. "High" (in JSON) -> Severity.HIGH (in Java).
            .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS);
    private final AstScaConfig astScaConfig;


    private String projectId;
    private String scanId;
    private final FingerprintCollector fingerprintCollector;
    private CxSCAResolvingConfiguration resolvingConfiguration;
    private static final String FINGERPRINT_FILE_NAME = ".cxsca.sig";

    public AstScaClient(CxScanConfig config, Logger log) {
        super(config, log);

        this.astScaConfig = config.getAstScaConfig();
        validate(astScaConfig);

        httpClient = createHttpClient(astScaConfig.getApiUrl());
        this.resolvingConfiguration = null;
        fingerprintCollector = new FingerprintCollector(log);
        // Pass tenant name in a custom header. This will allow to get token from on-premise access control server
        // and then use this token for SCA authentication in cloud.
        httpClient.addCustomHeader(TENANT_HEADER_NAME, config.getAstScaConfig().getTenant());
    }

    @Override
    protected String getScannerDisplayName() {
        return ScannerType.AST_SCA.getDisplayName();
    }

    @Override
    protected ScanConfig getScanConfig() {
        return ScanConfig.builder()
                .type(ENGINE_TYPE_FOR_API)
                .build();
    }

    @Override
    protected HandlerRef getBranchToScan(RemoteRepositoryInfo repoInfo) {
        if (StringUtils.isNotEmpty(repoInfo.getBranch())) {
            // If we pass the branch to start scan API, the API will return an error:
            // "Git references (branch, commit ID, etc.) are not yet supported."
            //
            // We can't just ignore the branch, because it will lead to confusion.
            String message = String.format("Branch specification is not yet supported by %s.", getScannerDisplayName());
            throw new CxClientException(message);
        }
        return null;
    }

    /**
     * Transforms the repo URL if credentials are specified in repoInfo.
     */
    @Override
    protected URL getEffectiveRepoUrl(RemoteRepositoryInfo repoInfo) {
        URL result;
        URL initialUrl = repoInfo.getUrl();

        // Otherwise we may get something like "https://mytoken:null@github.com".
        String username = StringUtils.defaultString(repoInfo.getUsername());
        String password = StringUtils.defaultString(repoInfo.getPassword());

        try {
            if (StringUtils.isNotEmpty(username) || StringUtils.isNotEmpty(password)) {
                log.info("Adding credentials as the userinfo part of the URL, because {} only supports this kind of authentication.",
                        getScannerDisplayName());

                result = new URIBuilder(initialUrl.toURI())
                        .setUserInfo(username, password)
                        .build()
                        .toURL();
            } else {
                result = repoInfo.getUrl();
            }
        } catch (Exception e) {
            throw new CxClientException("Error getting effective repo URL.");
        }
        return result;
    }

    @Override
    public void init() {
        try {
            login();
        } catch (IOException e) {
            throw new CxClientException("Failed to init CxSCA Client.", e);
        }
    }

    public CxSCAResolvingConfiguration getCxSCAResolvingConfigurationForProject(String projectId) throws IOException {
        log.info("Resolving configuration for project: {}", projectId);
        String path = String.format(UrlPaths.RESOLVING_CONFIGURATION_API, URLEncoder.encode(projectId, ENCODING));

        return httpClient.getRequest(path,
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                CxSCAResolvingConfiguration.class,
                HttpStatus.SC_OK,
                "get CxSCA resolving configuration",
                false);
    }

    /**
     * Waits for SCA scan to finish, then gets scan results.
     *
     * @throws CxClientException in case of a network error, scan failure or when scan is aborted by timeout.
     */
    @Override
    public Results waitForScanResults() {
        waitForScanToFinish(scanId);

        return tryGetScanResults(scanId)
                .orElseThrow(() -> new CxClientException("Unable to get scan results: scan not found."));
    }

    @Override
    public Results initiateScan() {
        log.info("----------------------------------- Initiating {} Scan:------------------------------------",
                getScannerDisplayName());
        AstScaResults scaResults = new AstScaResults();
        scanId = null;
        projectId = null;
        try {
            AstScaConfig scaConfig = config.getAstScaConfig();
            SourceLocationType locationType = scaConfig.getSourceLocationType();
            HttpResponse response;

            projectId = resolveRiskManagementProject();
            boolean isManifestAndFingerprintsOnly = !config.getAstScaConfig().isIncludeSources();
            if (isManifestAndFingerprintsOnly) {
                this.resolvingConfiguration = getCxSCAResolvingConfigurationForProject(this.projectId);
                log.info("Got the following manifest patterns {}", this.resolvingConfiguration.getManifests());
                log.info("Got the following fingerprint patterns {}", this.resolvingConfiguration.getFingerprints());
            }

            if (locationType == SourceLocationType.REMOTE_REPOSITORY) {
                response = submitSourcesFromRemoteRepo(scaConfig, projectId);
            } else {
                if (scaConfig.isIncludeSources()) {
                    response = submitAllSourcesFromLocalDir(projectId);
                } else {
                    response = submitManifestsAndFingerprintsFromLocalDir(projectId);
                }
            }
            this.scanId = extractScanIdFrom(response);
            scaResults.setScanId(scanId);
            return scaResults;
        } catch (IOException e) {
            throw new CxClientException("Error creating scan.", e);
        }
    }

    private HttpResponse submitManifestsAndFingerprintsFromLocalDir(String projectId) throws IOException {
        log.info("Using manifest only and fingerprint flow");

        String sourceDir = config.getEffectiveSourceDirForDependencyScan();

        PathFilter userFilter = new PathFilter(config.getOsaFolderExclusions(), config.getOsaFilterPattern(), log);
        Set<String> scannedFileSet = new HashSet<>(Arrays.asList(CxSCAFileSystemUtils.scanAndGetIncludedFiles(sourceDir, userFilter)));

        PathFilter manifestIncludeFilter = new PathFilter(null, getManifestsIncludePattern(), log);
        if (manifestIncludeFilter.getIncludes().length == 0) {
            throw new CxClientException(String.format("Using manifest only mode requires include filter. Resolving config does not have include patterns defined: %s", getManifestsIncludePattern()));
        }

        List<String> filesToZip =
                Arrays.stream(CxSCAFileSystemUtils.scanAndGetIncludedFiles(sourceDir, manifestIncludeFilter))
                        .filter(scannedFileSet::contains).
                        collect(Collectors.toList());

        List<String> filesToFingerprint =
                Arrays.stream(CxSCAFileSystemUtils.scanAndGetIncludedFiles(sourceDir,
                        new PathFilter(null, getFingerprintsIncludePattern(), log)))
                        .filter(scannedFileSet::contains).
                        collect(Collectors.toList());


        CxSCAScanFingerprints fingerprints = fingerprintCollector.collectFingerprints(sourceDir, filesToFingerprint);

        File zipFile = zipDirectoryAndFingerprints(sourceDir, filesToZip, fingerprints);

        optionallyWriteFingerprintsToFile(fingerprints);

        return initiateScanForUpload(projectId, zipFile);
    }


    private File zipDirectoryAndFingerprints(String sourceDir, List<String> paths, CxSCAScanFingerprints fingerprints) throws IOException {
        File result = config.getZipFile();
        if (result != null) {
            return result;
        }
        File tempFile = getZipFile();
        log.info("Collecting files to zip archive: {}", tempFile.getAbsolutePath());
        long maxZipSizeBytes = config.getMaxZipSize() != null ? config.getMaxZipSize() * 1024 * 1024 : MAX_ZIP_SIZE_BYTES;

        NewCxZipFile zipper = null;
        try {
            zipper = new NewCxZipFile(tempFile, maxZipSizeBytes, log);
            zipper.addMultipleFilesToArchive(new File(sourceDir), paths);
            if (zipper.getFileCount() == 0 && fingerprints.getFingerprints().isEmpty()) {
                throw handleFileDeletion(tempFile);
            }
            if (!fingerprints.getFingerprints().isEmpty()) {
                zipper.zipContentAsFile(FINGERPRINT_FILE_NAME, FingerprintCollector.getFingerprintsAsJsonString(fingerprints).getBytes());
            } else {
                log.info("No supported fingerprints found to zip");
            }

            log.debug("The sources were zipped to {}", tempFile.getAbsolutePath());
            return tempFile;
        } catch (Zipper.MaxZipSizeReached e) {
            throw handleFileDeletion(tempFile, new IOException("Reached maximum upload size limit of " + FileUtils.byteCountToDisplaySize(maxZipSizeBytes)));
        } catch (IOException ioException) {
            throw handleFileDeletion(tempFile, ioException);
        } finally {
            if (zipper != null) {
                zipper.close();
            }
        }

    }

    private CxClientException handleFileDeletion(File file, IOException ioException) {
        try {
            Files.delete(file.toPath());
        } catch (IOException e) {
            return new CxClientException(e);
        }

        return new CxClientException(ioException);

    }

    private CxClientException handleFileDeletion(File file) {
        try {
            Files.delete(file.toPath());
        } catch (IOException e) {
            return new CxClientException(e);
        }

        return new CxClientException("No files found to zip and no supported fingerprints found");
    }

    private String getFingerprintsIncludePattern() {
        if (StringUtils.isNotEmpty(astScaConfig.getFingerprintsIncludePattern())) {
            return astScaConfig.getFingerprintsIncludePattern();
        }

        return resolvingConfiguration.getFingerprintsIncludePattern();
    }

    private String getManifestsIncludePattern() {
        if (StringUtils.isNotEmpty(astScaConfig.getManifestsIncludePattern())) {
            return astScaConfig.getManifestsIncludePattern();
        }

        return resolvingConfiguration.getManifestsIncludePattern();
    }

    private File getZipFile() throws IOException {
        if (StringUtils.isNotEmpty(astScaConfig.getZipFilePath())) {
            return new File(astScaConfig.getZipFilePath());
        }
        return File.createTempFile(TEMP_FILE_NAME_TO_ZIP, ".bin");
    }

    private void optionallyWriteFingerprintsToFile(CxSCAScanFingerprints fingerprints) {
        if (StringUtils.isNotEmpty(astScaConfig.getFingerprintFilePath())) {
            try {
                fingerprintCollector.writeScanFingerprintsFile(fingerprints, astScaConfig.getFingerprintFilePath());
            } catch (IOException ioException) {
                log.error(String.format("Failed writing fingerprint file to %s", astScaConfig.getFingerprintFilePath()), ioException);
            }
        }
    }

    private HttpResponse submitAllSourcesFromLocalDir(String projectId) throws IOException {
        log.info("Using local directory flow.");

        PathFilter filter = new PathFilter(config.getOsaFolderExclusions(), config.getOsaFilterPattern(), log);
        String sourceDir = config.getEffectiveSourceDirForDependencyScan();
        File zipFile = CxZipUtils.getZippedSources(config, filter, sourceDir, log);

        return initiateScanForUpload(projectId, zipFile);
    }

    /**
     * Gets latest scan results using {@link CxScanConfig#getProjectName()} for the current config.
     *
     * @return results of the latest successful scan for a project, if present; null - otherwise.
     */
    @Override
    public Results getLatestScanResults() {
        AstScaResults result;
        try {
            log.info("Getting latest scan results.");
            projectId = getRiskManagementProjectId(config.getProjectName());
            scanId = getLatestScanId(projectId);
            result = tryGetScanResults(scanId).orElse(null);
        } catch (IOException e) {
            throw new CxClientException("Error getting latest scan results.", e);
        }
        return result;
    }

    private Optional<AstScaResults> tryGetScanResults(String scanId) {
        AstScaResults result = null;
        if (StringUtils.isNotEmpty(scanId)) {
            result = getScanResults(scanId);
        } else {
            log.info("Unable to get scan results");
        }
        return Optional.ofNullable(result);
    }

    private HttpResponse initiateScanForUpload(String projectId, File zipFile) throws IOException {
        String uploadedArchiveUrl = getSourcesUploadUrl();
        String cleanPath = uploadedArchiveUrl.split("\\?")[0];
        log.info("Uploading to: {}", cleanPath);
        uploadArchive(zipFile, uploadedArchiveUrl);

        //delete only if path not specified in the config
        if (StringUtils.isEmpty(astScaConfig.getZipFilePath())) {
            CxZipUtils.deleteZippedSources(zipFile, config, log);
        }

        RemoteRepositoryInfo uploadedFileInfo = new RemoteRepositoryInfo();
        uploadedFileInfo.setUrl(new URL(uploadedArchiveUrl));

        return sendStartScanRequest(uploadedFileInfo, SourceLocationType.LOCAL_DIRECTORY, projectId);
    }

    private String getLatestScanId(String projectId) throws IOException {
        String result = null;
        if (StringUtils.isNotEmpty(projectId)) {
            log.debug("Getting latest scan ID for project ID: {}", projectId);
            String path = String.format(UrlPaths.LATEST_SCAN, URLEncoder.encode(projectId, ENCODING));
            JsonNode response = httpClient.getRequest(path,
                    ContentType.CONTENT_TYPE_APPLICATION_JSON,
                    ArrayNode.class,
                    HttpStatus.SC_OK,
                    "scan ID by project ID",
                    false);

            result = Optional.ofNullable(response)
                    // 'riskReportId' is in fact scanId, but the name is kept for backward compatibility.
                    .map(resp -> resp.at("/0/riskReportId").textValue())
                    .orElse(null);
        }
        String message = (result == null ? "Scan not found" : String.format("Scan ID: %s", result));
        log.info(message);
        return result;
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

        CxHttpClient uploader = createHttpClient(uploadUrl);

        // Relative path is empty, because we use the whole upload URL as the base URL for the HTTP client.
        // Content type is empty, because the server at uploadUrl throws an error if Content-Type is non-empty.
        uploader.putRequest("", "", request, JsonNode.class, HttpStatus.SC_OK, "upload ZIP file");
    }

    private void printWebReportLink(AstScaResults scaResult) {
        if (!StringUtils.isEmpty(scaResult.getWebReportLink())) {
            log.info("{} scan results location: {}", getScannerDisplayName(), scaResult.getWebReportLink());
        }
    }

    void testConnection() throws IOException {
        // The calls below allow to check both access control and API connectivity.
        login();
        getRiskManagementProjects();
    }

    public void login() throws IOException {
        log.info("Logging into {}", getScannerDisplayName());
        AstScaConfig scaConfig = config.getAstScaConfig();

        LoginSettings settings = new LoginSettings();

        String acUrl = scaConfig.getAccessControlUrl();

        settings.setAccessControlBaseUrl(acUrl);
        settings.setUsername(scaConfig.getUsername());
        settings.setPassword(scaConfig.getPassword());
        settings.setTenant(scaConfig.getTenant());

        ClientTypeResolver resolver = new ClientTypeResolver();
        ClientType clientType = resolver.determineClientType(acUrl);
        settings.setClientTypeForPasswordAuth(clientType);

        httpClient.login(settings);
    }

    public void close() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

    /**
     * The following config properties are used:
     * astScaConfig
     * proxyConfig
     * cxOrigin
     * disableCertificateValidation
     */
    public void testScaConnection() {
        try {
            testConnection();
        } catch (IOException e) {
            throw new CxClientException(e);
        }
    }

    private String resolveRiskManagementProject() throws IOException {
        String projectName = config.getProjectName();
        log.info("Getting project by name: '{}'", projectName);
        String resolvedProjectId = getRiskManagementProjectId(projectName);
        if (resolvedProjectId == null) {
            log.info("Project not found, creating a new one.");
            resolvedProjectId = createRiskManagementProject(projectName);
            log.info("Created a project with ID {}", resolvedProjectId);
        } else {
            log.info("Project already exists with ID {}", resolvedProjectId);
        }
        return resolvedProjectId;
    }

    private String getRiskManagementProjectId(String projectName) throws IOException {
        log.info("Getting project ID by name: '{}'", projectName);

        if (StringUtils.isEmpty(projectName)) {
            throw new CxClientException("Non-empty project name must be provided.");
        }

        Project project = sendGetProjectRequest(projectName);

        String result = Optional.ofNullable(project)
                .map(Project::getId)
                .orElse(null);

        String message = (result == null ? "Project not found" : String.format("Project ID: %s", result));
        log.info(message);

        return result;
    }

    private Project sendGetProjectRequest(String projectName) throws IOException {
        Project result;
        try {
            String getProjectByName = String.format("%s?name=%s", UrlPaths.PROJECTS, URLEncoder.encode(projectName, ENCODING));
            result = httpClient.getRequest(getProjectByName,
                    ContentType.CONTENT_TYPE_APPLICATION_JSON,
                    Project.class,
                    HttpStatus.SC_OK,
                    "CxSCA project ID by name",
                    false);
        } catch (CxHTTPClientException e) {
            if (e.getStatusCode() == HttpStatus.SC_NOT_FOUND) {
                result = null;
            } else {
                throw e;
            }
        }
        return result;
    }

    private void getRiskManagementProjects() throws IOException {
        httpClient.getRequest(UrlPaths.PROJECTS,
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                Project.class,
                HttpStatus.SC_OK,
                "CxSCA projects",
                true);
    }

    private String createRiskManagementProject(String name) throws IOException {
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

    private AstScaResults getScanResults(String scanId) {
        AstScaResults result;
        log.debug("Getting results for scan ID {}", scanId);
        try {
            result = new AstScaResults();
            result.setScanId(this.scanId);

            AstScaSummaryResults scanSummary = getSummaryReport(scanId);
            result.setSummary(scanSummary);
            printSummary(scanSummary, this.scanId);

            List<Finding> findings = getFindings(scanId);
            result.setFindings(findings);

            List<Package> packages = getPackages(scanId);
            result.setPackages(packages);

            String reportLink = getWebReportLink(scanId);
            result.setWebReportLink(reportLink);
            printWebReportLink(result);
            result.setScaResultReady(true);
            log.info("Retrieved SCA results successfully.");
        } catch (IOException e) {
            throw new CxClientException("Error retrieving CxSCA scan results.", e);
        }
        return result;
    }

    private String getWebReportLink(String scanId) {
        final String MESSAGE = "Unable to generate web report link.";
        String result = null;
        try {
            String webAppUrl = config.getAstScaConfig().getWebAppUrl();
            if (StringUtils.isEmpty(webAppUrl)) {
                log.warn("{} Web app URL is not specified.", MESSAGE);
            } else {
                String path = String.format(UrlPaths.WEB_REPORT,
                        URLEncoder.encode(projectId, ENCODING),
                        URLEncoder.encode(scanId, ENCODING));

                result = UrlUtils.parseURLToString(webAppUrl, path);
            }
        } catch (MalformedURLException e) {
            log.warn("Unable to generate web report link: invalid web app URL.", e);
        } catch (Exception e) {
            log.warn("Unable to generate web report link: general error.", e);
        }
        return result;
    }

    private AstScaSummaryResults getSummaryReport(String scanId) throws IOException {
        log.debug("Getting summary report.");

        String path = String.format(UrlPaths.SUMMARY_REPORT, URLEncoder.encode(scanId, ENCODING));

        return httpClient.getRequest(path,
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                AstScaSummaryResults.class,
                HttpStatus.SC_OK,
                "CxSCA report summary",
                false);
    }

    private List<Finding> getFindings(String scanId) throws IOException {
        log.debug("Getting findings.");

        String path = String.format(UrlPaths.FINDINGS, URLEncoder.encode(scanId, ENCODING));

        ArrayNode responseJson = httpClient.getRequest(path,
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                ArrayNode.class,
                HttpStatus.SC_OK,
                "CxSCA findings",
                false);

        Finding[] findings = caseInsensitiveObjectMapper.treeToValue(responseJson, Finding[].class);

        return Arrays.asList(findings);
    }

    private List<Package> getPackages(String scanId) throws IOException {
        log.debug("Getting packages.");

        String path = String.format(UrlPaths.PACKAGES, URLEncoder.encode(scanId, ENCODING));

        return (List<Package>) httpClient.getRequest(path,
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                Package.class,
                HttpStatus.SC_OK,
                "CxSCA findings",
                true);
    }

    private void printSummary(AstScaSummaryResults summary, String scanId) {
        if (log.isInfoEnabled()) {
            log.info("----CxSCA risk report summary----");
            log.info("Created on: {}", summary.getCreatedOn());
            log.info("Direct packages: {}", summary.getDirectPackages());
            log.info("High vulnerabilities: {}", summary.getHighVulnerabilityCount());
            log.info("Medium vulnerabilities: {}", summary.getMediumVulnerabilityCount());
            log.info("Low vulnerabilities: {}", summary.getLowVulnerabilityCount());
            log.info("Scan ID: {}", scanId);
            log.info(String.format("Risk score: %.2f", summary.getRiskScore()));
            log.info("Total packages: {}", summary.getTotalPackages());
            log.info("Total outdated packages: {}", summary.getTotalOutdatedPackages());
        }
    }

    private void validate(AstScaConfig config) {
        String error = null;
        if (config == null) {
            error = "%s config must be provided.";
        } else if (StringUtils.isEmpty(config.getApiUrl())) {
            error = "%s API URL must be provided.";
        } else if (StringUtils.isEmpty(config.getAccessControlUrl())) {
            error = "%s access control URL must be provided.";
        } else {
            RemoteRepositoryInfo repoInfo = config.getRemoteRepositoryInfo();
            if (repoInfo == null && config.getSourceLocationType() == SourceLocationType.REMOTE_REPOSITORY) {
                error = "%s remote repository info must be provided.";
            } else if (repoInfo != null && StringUtils.isNotEmpty(repoInfo.getBranch())) {
                error = "%s doesn't support specifying custom branches. It currently uses the default branch of a repo.";
            }
        }

        if (error != null) {
            throw new IllegalArgumentException(String.format(error, getScannerDisplayName()));
        }
    }
}