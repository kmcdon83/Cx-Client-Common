package com.cx.restclient.common;

import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.osa.dto.OSAResults;

/**
 * Dependency Scanner is an umbrella term for OSA and SCA.
 */
public interface DependencyScanner {
    void init() throws CxClientException;

    String createScan() throws CxClientException;

    OSAResults waitForScanResults() throws CxClientException;

    OSAResults getLatestScanResults() throws CxClientException;
}
