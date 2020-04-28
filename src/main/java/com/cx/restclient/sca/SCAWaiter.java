package com.cx.restclient.sca;

import com.cx.restclient.SCAClient;
import com.cx.restclient.common.ShragaUtils;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.httpClient.CxHttpClient;
import com.cx.restclient.httpClient.utils.ContentType;
import com.cx.restclient.sca.dto.ScanInfoResponse;
import com.cx.restclient.sca.dto.ScanStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;
import org.awaitility.core.ConditionTimeoutException;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

@RequiredArgsConstructor
@Slf4j
public class SCAWaiter {
    private final CxHttpClient httpClient;
    private final CxScanConfig config;
    private long startTimestampSec;

    public void waitForScanToComplete(String scanId) {
        startTimestampSec = System.currentTimeMillis() / 1000;
        Duration timeout = getTimeout(config);
        Duration pollInterval = getPollInterval(config);

        int maxErrorCount = getMaxErrorCount(config);
        AtomicInteger errorCounter = new AtomicInteger();

        String urlPath = String.format(SCAClient.UrlPaths.GET_SCAN, scanId);

        try {
            Awaitility.await()
                    .atMost(timeout)
                    .pollDelay(Duration.ZERO)
                    .pollInterval(pollInterval)
                    .until(() -> scanIsCompleted(urlPath, errorCounter, maxErrorCount));

        } catch (ConditionTimeoutException e) {
            String message = String.format(
                    "Failed to perform CxSCA scan. The scan has been automatically aborted: " +
                            "reached the user-specified timeout (%d minutes).", timeout.toMinutes());
            throw new CxClientException(message);
        }
    }

    private static Duration getTimeout(CxScanConfig config) {
        Integer rawTimeout = config.getOsaScanTimeoutInMinutes();
        final int DEFAULT_TIMEOUT = 30;
        rawTimeout = rawTimeout != null && rawTimeout > 0 ? rawTimeout : DEFAULT_TIMEOUT;
        return Duration.ofMinutes(rawTimeout);
    }

    private static Duration getPollInterval(CxScanConfig config) {
        int rawPollInterval = ObjectUtils.defaultIfNull(config.getOsaProgressInterval(), 20);
        return Duration.ofSeconds(rawPollInterval);
    }

    private static int getMaxErrorCount(CxScanConfig config) {
        return ObjectUtils.defaultIfNull(config.getConnectionRetries(), 3);
    }

    private boolean scanIsCompleted(String path, AtomicInteger errorCounter, int maxErrorCount) {
        boolean completedSuccessfully = false;
        try {
            ScanInfoResponse response = httpClient.getRequest(path, ContentType.CONTENT_TYPE_APPLICATION_JSON,
                    ScanInfoResponse.class, HttpStatus.SC_OK, "CxSCA scan", false);

            completedSuccessfully = validateScanStatus(response);
        } catch (Exception e) {
            countError(errorCounter, maxErrorCount, e.getMessage());
        }
        return completedSuccessfully;
    }

    private void countError(AtomicInteger errorCounter, int maxErrorCount, String message) {
        int currentErrorCount = errorCounter.incrementAndGet();
        int triesLeft = maxErrorCount - currentErrorCount;
        if (triesLeft < 0) {
            String fullMessage = String.format("Maximum number of errors was reached (%d), aborting.", maxErrorCount);
            throw new CxClientException(fullMessage);
        } else {
            log.info("Failed to get status from CxSCA. Retrying (tries left: {}). Error message: {}", triesLeft, message);
        }
    }

    private boolean validateScanStatus(ScanInfoResponse response) {
        if (response == null) {
            throw new CxClientException("Empty response.");
        }

        String rawStatus = response.getStatus();
        String elapsedTimestamp = ShragaUtils.getTimestampSince(startTimestampSec);
        log.info("Waiting for CxSCA scan results. Elapsed time: {}. Status: {}.", elapsedTimestamp, rawStatus);
        ScanStatus status = EnumUtils.getEnumIgnoreCase(ScanStatus.class, rawStatus);

        boolean completedSuccessfully = false;
        if (status == ScanStatus.COMPLETED) {
            completedSuccessfully = true;
        } else if (status == ScanStatus.FAILED) {
            throw new CxClientException("CxSCA scan cannot be completed.");
        } else if (status == null) {
            log.warn("Unknown status: {}", rawStatus);
        }
        return completedSuccessfully;
    }
}
