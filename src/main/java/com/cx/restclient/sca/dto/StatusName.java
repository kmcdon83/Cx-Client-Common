package com.cx.restclient.sca.dto;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum StatusName {
    FAILED("Failed"),
    DONE("Done"),
    SCANNING("Scanning");

    private final String value;

    @JsonValue
    public String getValue() {
        return value;
    }
}
