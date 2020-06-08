package com.cx.restclient.common;

import com.cx.restclient.dto.BaseStatus;
import com.cx.restclient.dto.Status;
import com.cx.restclient.exception.CxClientException;
import org.slf4j.Logger;

import java.io.IOException;
import java.util.Date;

/**
 * Created by Galn on 13/02/2018.
 */
public abstract class Waiter<T> {

    private static final String FAILED_MSG = "Failed to get status from ";

    private int retry;
    private String scanType;
    private int sleepIntervalSec;

    public Waiter(String scanType, int interval, int retry) {
        this.scanType = scanType;
        this.sleepIntervalSec = interval;
        this.retry = retry;
    }

    private long startTimeSec;

    public T waitForTaskToFinish(String taskId, Integer scanTimeoutSec, Logger log) throws CxClientException {
        startTimeSec = System.currentTimeMillis() / 1000;
        long elapsedTimeSec = 0L;
        T statusResponse;

        try {
            statusResponse = getStatus(taskId);

            while (isTaskInProgress(statusResponse) && (scanTimeoutSec <= 0 || elapsedTimeSec < scanTimeoutSec)) {
                Thread.sleep((long)sleepIntervalSec * 1000);
                try {
                    statusResponse = getStatus(taskId);
                } catch (Exception e) {
                    log.debug(FAILED_MSG + scanType + ". retrying (" + (retry - 1) + " tries left). Error message: " + e.getMessage());
                    retry--;
                    if (retry <= 0) {
                        throw new CxClientException(FAILED_MSG + scanType + ". Error message: " + e.getMessage(), e);
                    }
                    continue;
                }
                elapsedTimeSec = (new Date()).getTime() / 1000 - startTimeSec;
                printProgress(statusResponse);
            }

            if (scanTimeoutSec > 0 && scanTimeoutSec <= elapsedTimeSec) {
                throw new CxClientException("Failed to perform " + scanType + ": " + scanType + " has been automatically aborted: reached the user-specified timeout (" + scanTimeoutSec / 60 + " minutes)");
            }
        } catch (Exception e) {
            throw new CxClientException(FAILED_MSG + scanType + ". Error message: " + e.getMessage(), e);
        }
        return resolveStatus(statusResponse);
    }

    public abstract T getStatus(String id) throws CxClientException, IOException;

    public abstract void printProgress(T status);

    public abstract T resolveStatus(T status) throws CxClientException;

    public boolean isTaskInProgress(T statusResponse) {
        Status status = ((BaseStatus) statusResponse).getBaseStatus();
        return status.equals(Status.IN_PROGRESS);
    }

    public long getStartTimeSec() {
        return startTimeSec;
    }
}
