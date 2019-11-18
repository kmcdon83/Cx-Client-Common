package com.cx.restclient.sast.dto;

/**
 * Created by Galn on 07/03/2018.
 */
public enum CxARMStatusEnum {

    IN_PROGRESS("InProgress"),
    FINISHED("Finished"),
    FAILED("Failed"),
    NONE("None");

    private final String value;

    CxARMStatusEnum(String value) {
        this.value = value;
    }

    public String value() {
        return this.value;
    }


}

