package com.cx.restclient.common;

import com.cx.restclient.dto.Results;
import com.cx.restclient.sast.utils.State;

/**
 * Common functionality for vulnerability scanners.
 */
public interface Scanner {
    Results init();

    Results initiateScan();

    Results waitForScanResults();

    Results getLatestScanResults();

    void close();

    default State getState() {
        return State.SUCCESS;
    }
}
