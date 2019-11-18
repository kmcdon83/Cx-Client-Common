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

    private int retry = 5;
    private String scanType;
    private int sleepIntervalSec;

    public Waiter(String scanType, int interval) {
        this.scanType = scanType;
        this.sleepIntervalSec = interval;
    }

    private long startTimeSec;

    protected Status status = null;

    public T waitForTaskToFinish(String taskId, Integer scanTimeoutSec, Logger log) throws CxClientException, InterruptedException {
        startTimeSec = System.currentTimeMillis() / 1000;
        long elapsedTimeSec = 0L;
        status = Status.IN_PROGRESS;
        T obj = null;

        while (status.equals(Status.IN_PROGRESS) && (scanTimeoutSec <= 0 || elapsedTimeSec < scanTimeoutSec)) {
            Thread.sleep(sleepIntervalSec * 1000);
            try {
                obj = getStatus(taskId);
                status = ((BaseStatus) obj).getBaseStatus();
            } catch (Exception e) {
                log.debug("Failed to get status from " + scanType + ". retrying (" + (retry - 1) + " tries left). Error message: " + e.getMessage());
                if (retry <= 0) {
                    throw new CxClientException("Failed to get status from " + scanType + ". Error message: " + e.getMessage(), e);
                }
                retry--;
                continue;
            }
            elapsedTimeSec = (new Date()).getTime() / 1000 - startTimeSec;
            printProgress(obj);

        }
        if (scanTimeoutSec > 0 && scanTimeoutSec <= elapsedTimeSec) {
            throw new CxClientException( "Failed to perform " + scanType + ": " + scanType + " has been automatically aborted: reached the user-specified timeout (" + scanTimeoutSec / 60 + " minutes)");
        }
        return resolveStatus(obj);
    }

    public abstract T getStatus(String id) throws CxClientException, IOException;

    public abstract void printProgress(T status);

    public abstract T resolveStatus(T status) throws CxClientException;

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public long getStartTimeSec() {
        return startTimeSec;
    }
}
