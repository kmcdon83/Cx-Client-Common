package com.cx.restclient.sast.dto;

/**
 * Created by Galn on 07/03/2018.
 */
public enum ReportStatusEnum {

    DELETED("Deleted"),
    INPROCESS("InProcess"),
    CREATED("Created"),
    FAILED("Failed");

    private final String value;

    ReportStatusEnum(String value) {
        this.value = value;
    }

    public String value() {
        return this.value;
    }


}

