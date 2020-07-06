package com.cx.restclient;

import com.cx.restclient.ast.dto.ASTConfig;
import com.cx.restclient.common.IScanner;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.ScanResults;
import com.cx.restclient.httpClient.CxHttpClient;
import org.apache.commons.lang.NotImplementedException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;

public class ASTClient implements IScanner {
    private final CxScanConfig config;
    private final Logger log;
    private final CxHttpClient httpClient;

    public static class UrlPaths {
        private UrlPaths() {
        }

        public static final String SCANS = "api/scans";
    }

    public ASTClient(CxScanConfig config, Logger log) {
        this.config = config;
        this.log = log;

        ASTConfig astConfig = this.config.getAstConfig();
        String normalizedUrl = StringUtils.appendIfMissing(astConfig.getApiBaseUrl(), "/");
        httpClient = createHttpClient(normalizedUrl);
    }

    @Override
    public void init() {
        // Nothing to do here yet.
    }

    @Override
    public ScanResults createScan() {
        return null;
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
