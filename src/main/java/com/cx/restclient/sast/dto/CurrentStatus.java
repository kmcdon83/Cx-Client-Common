package com.cx.restclient.sast.dto;

/**
 * Created by Galn on 05/02/2018.
 */
public enum CurrentStatus {

    QUEUED("Queued"),
    WORKING("Working"),
    FINISHED("Finished"),
    FAILED("Failed"),
    CANCELED("Canceled"),
    DELETED("Deleted"),
    UNKNOWN("Unknown"),
    UNZIPPING("Unzipping"),
    WAITING_TO_PROCESS("WaitingToProcess");

    private final String value;

    CurrentStatus(String value) {
        this.value = value;
    }

    public String value() {
        return this.value;
    }
}
