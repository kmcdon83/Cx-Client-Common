package com.cx.restclient.ast;

import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.SourceLocationType;
import com.cx.restclient.httpClient.CxHttpClient;
import com.cx.restclient.httpClient.utils.ContentType;
import com.cx.restclient.httpClient.utils.HttpClientHelper;
import com.cx.restclient.sca.dto.ProjectToScan;
import com.cx.restclient.sca.dto.ScanStartHandler;
import com.cx.restclient.sca.dto.StartScanRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;

import java.io.IOException;

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
}
