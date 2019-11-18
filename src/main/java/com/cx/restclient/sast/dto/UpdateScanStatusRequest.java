package com.cx.restclient.sast.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Created by Galn on 18/03/2018.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class UpdateScanStatusRequest {
    private String status;

    public UpdateScanStatusRequest(CurrentStatus status) {
        this.status = status.value();
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(CurrentStatus status) {
        this.status = status.value();
    }
}
