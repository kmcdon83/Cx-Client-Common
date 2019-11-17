package com.cx.restclient.sca;

import com.cx.restclient.common.ShragaUtils;
import com.cx.restclient.common.Waiter;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.httpClient.CxHttpClient;
import com.cx.restclient.httpClient.utils.ContentType;
import com.cx.restclient.sca.dto.ScanStatusResponse;
import com.cx.restclient.sca.dto.StatusName;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;

import java.io.IOException;

public class SCAWaiter extends Waiter<ScanStatusResponse> {
    private final CxHttpClient httpClient;
    private final Logger log;

    public SCAWaiter(String scanType, int interval, int retry, CxHttpClient httpClient, Logger log) {
        super(scanType, interval, retry);
        this.httpClient = httpClient;
        this.log = log;
    }

    @Override
    public ScanStatusResponse getStatus(String scanId) throws CxClientException, IOException {
        String path = String.format("scans/%s/status", scanId);

        ScanStatusResponse response = httpClient.getRequest(path,
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                ScanStatusResponse.class, HttpStatus.SC_OK,
                "SCA scan status",
                false);

        return response;
    }

    @Override
    public void printProgress(ScanStatusResponse statusResponse) {
        log.info(String.format("Waiting for SCA scan results. Elapsed time: %s. Status: %s.",
                ShragaUtils.getTimestampSince(getStartTimeSec()),
                statusResponse.getName().getValue()));
    }

    @Override
    public ScanStatusResponse resolveStatus(ScanStatusResponse lastStatusResponse) throws CxClientException {
        if (lastStatusResponse == null || lastStatusResponse.getName() == StatusName.FAILED) {
            String details = null;
            if (lastStatusResponse != null) {
                details = String.format("Status: %s, message: \'%s\'",
                        lastStatusResponse.getName(),
                        lastStatusResponse.getMessage());
            }
            throw new CxClientException("SCA scan cannot be completed. " + details);
        }

        if (lastStatusResponse.getName() == StatusName.DONE) {
            log.info("SCA scan finished.");
        }
        return lastStatusResponse;
    }

    @Override
    public boolean isTaskInProgress(ScanStatusResponse statusResponse) {
        return statusResponse != null && statusResponse.getName() == StatusName.SCANNING;
    }
}
