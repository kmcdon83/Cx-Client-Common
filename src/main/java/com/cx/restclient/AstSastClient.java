package com.cx.restclient;

import com.cx.restclient.ast.AstClient;
import com.cx.restclient.ast.dto.ASTConfig;
import com.cx.restclient.ast.dto.AstSastConfig;
import com.cx.restclient.common.Scanner;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.Results;
import com.cx.restclient.dto.ScanResults;
import com.cx.restclient.dto.SourceLocationType;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.sca.dto.ASTResults;
import org.apache.commons.lang.NotImplementedException;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AUTH;
import org.slf4j.Logger;

import java.io.IOException;

public class AstSastClient extends AstClient implements Scanner {

    public AstSastClient(CxScanConfig config, Logger log) {
        super(config, log);

        ASTConfig astConfig = this.config.getAstConfig();
        String normalizedUrl = StringUtils.stripEnd(astConfig.getApiUrl(), "/");

        httpClient = createHttpClient(normalizedUrl);
    }

    @Override
    public void init() {
        AstSastConfig astConfig = config.getAstConfig();
        httpClient.addCustomHeader(AUTH.WWW_AUTH_RESP, String.format("Bearer %s", astConfig.getAccessToken()));

    }

    @Override
    public Results initiateScan() {
        ASTResults astResults = new ASTResults();
        ASTConfig astConfig = config.getAstConfig();
        try {
            SourceLocationType locationType = astConfig.getSourceLocationType();
            HttpResponse response;
            if (locationType == SourceLocationType.REMOTE_REPOSITORY) {
                response = submitSourcesFromRemoteRepo(astConfig, config.getProjectName());
            } else {
                throw new NotImplementedException("The upload flow is not yet supported.");
            }
            String scanId = extractScanIdFrom(response);
            log.info(String.format("Scan started successfully. Scan ID: %s", scanId));

            astResults.setScanId(scanId);
            return astResults;
        } catch (IOException e) {
            throw new CxClientException("Error creating CxAST-SAST scan.", e);
        }
    }

    @Override
    public ScanResults waitForScanResults() {
        return null;
    }

    @Override
    public ScanResults getLatestScanResults() {
        return null;
    }

    @Override
    public void close() {
        throw new NotImplementedException();
    }
}
