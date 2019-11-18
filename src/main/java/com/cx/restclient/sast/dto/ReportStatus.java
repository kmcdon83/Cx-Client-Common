package com.cx.restclient.sast.dto;

import com.cx.restclient.dto.BaseStatus;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Created by Galn on 07/03/2018.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ReportStatus extends BaseStatus {
    private String contentType;
    private CxValueObj status;

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public CxValueObj getStatus() {
        return status;
    }

    public void setStatus(CxValueObj status) {
        this.status = status;
    }
}
