package com.cx.restclient;

import com.cx.restclient.common.IScanner;
import com.cx.restclient.dto.IResults;
import com.cx.restclient.exception.CxClientException;

import java.io.IOException;

public class ASTClient implements IScanner {
    @Override
    public void init() throws CxClientException {

    }

    @Override
    public IResults createScan() throws CxClientException {
        return null;
    }

    @Override
    public IResults waitForScanResults() throws CxClientException, InterruptedException {
        return null;
    }

    @Override
    public IResults getLatestScanResults() throws CxClientException, InterruptedException {
        return null;
    }

    @Override
    public void login() throws IOException {

    }

    @Override
    public void close() {

    }
}
