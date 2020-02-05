package com.cx.restclient.sca.dto;

public class ScanStatusResponse {
    private StatusName name;
    private String message;

    public StatusName getName() {
        return name;
    }

    public void setName(StatusName name) {
        this.name = name;
    }

    public String getMessage() {
        return message;
    }
}
