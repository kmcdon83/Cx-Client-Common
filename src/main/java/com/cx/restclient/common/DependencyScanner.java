package com.cx.restclient.common;

import com.cx.restclient.dto.DependencyScanResults;
import com.cx.restclient.exception.CxClientException;

/**
 * Dependency Scanner is an umbrella term for OSA and SCA.
 */
public interface DependencyScanner {
    void init() throws CxClientException;

    String createScan(DependencyScanResults target) throws CxClientException;

    void waitForScanResults(DependencyScanResults target) throws CxClientException;

    DependencyScanResults getLatestScanResults() throws CxClientException;
}
