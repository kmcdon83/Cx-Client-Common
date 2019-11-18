package com.cx.restclient.cxArm.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Created by Galn on 7/8/2018.
 */

@JsonIgnoreProperties(ignoreUnknown = true)
public enum CxProviders {
    OPEN_SOURCE("open_source"),
    SAST("sast");
    private String value;

    public String value() {
        return value;
    }

    CxProviders(String value) {
        this.value = value;
    }
}
