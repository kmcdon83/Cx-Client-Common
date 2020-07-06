package com.cx.restclient;

import com.cx.restclient.ast.AstClient;
import com.cx.restclient.ast.dto.ASTConfig;
import com.cx.restclient.common.Scanner;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.ScanResults;
import org.apache.commons.lang.NotImplementedException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;

public class AstSastClient extends AstClient implements Scanner {

    public AstSastClient(CxScanConfig config, Logger log) {
        super(config, log);

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
}
