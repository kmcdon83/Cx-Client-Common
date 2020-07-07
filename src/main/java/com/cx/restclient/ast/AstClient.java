package com.cx.restclient.ast;

import com.cx.restclient.ast.dto.ASTConfig;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.SourceLocationType;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.httpClient.CxHttpClient;
import com.cx.restclient.httpClient.utils.ContentType;
import com.cx.restclient.httpClient.utils.HttpClientHelper;
import com.cx.restclient.sca.dto.*;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

public abstract class AstClient {
    protected final CxScanConfig config;
    protected final Logger log;

    // This class uses its own instance of CxHttpClient, because SCA has a different base URL and Access Control server.
    protected CxHttpClient httpClient;

    public AstClient(CxScanConfig config, Logger log) {
        this.config = config;
        this.log = log;
    }

    protected CxHttpClient createHttpClient(String baseUrl) {
        return new CxHttpClient(baseUrl,
                config.getCxOrigin(),
                config.isDisableCertificateValidation(),
                config.isUseSSOLogin(),
                null,
                config.getProxyConfig(),
                log);
    }

    protected HttpResponse sendStartScanRequest(SourceLocationType sourceLocation, String sourceUrl, String projectId) throws IOException {
        log.info("Sending a request to start scan.");

        HandlerRef ref = HandlerRef.builder().type("branch").value("").build();

        GitCredentials credentials = GitCredentials.builder().type("password").value("").build();

        ScanStartHandler handler = ScanStartHandler.builder()
                .url(sourceUrl)
                .ref(ref)
                .credentials(credentials)
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

    protected HttpResponse submitSourcesFromRemoteRepo(ASTConfig config, String projectId) throws IOException {
        log.info("Using remote repository flow.");
        RemoteRepositoryInfo repoInfo = config.getRemoteRepositoryInfo();
        validateRemoteRepoConfig(repoInfo);

        URL sanitizedUrl = sanitize(repoInfo.getUrl());
        log.info(String.format("Repository URL: %s", sanitizedUrl));

        return sendStartScanRequest(SourceLocationType.REMOTE_REPOSITORY, repoInfo.getUrl().toString(), projectId);
    }

    /**
     * Removes the userinfo part of the input URL (if present), so that the URL may be logged safely.
     * The URL may contain userinfo when a private repo is scanned.
     */
    private URL sanitize(URL url) throws MalformedURLException {
        return new URL(url.getProtocol(), url.getHost(), url.getFile());
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

    protected static String extractScanIdFrom(HttpResponse response) {
        if (response != null && response.getLastHeader("Location") != null) {
            // Expecting values like
            //      /api/scans/1ecffa00-0e42-49b2-8755-388b9f6a9293
            //      /07e5b4b0-184a-458e-9d82-7f3da407f940
            String urlPathWithScanId = response.getLastHeader("Location").getValue();
            String lastPathSegment = FilenameUtils.getName(urlPathWithScanId);
            if (StringUtils.isNotEmpty(lastPathSegment)) {
                return lastPathSegment;
            }
        }
        throw new CxClientException("Unable to get scan ID.");
    }
}
