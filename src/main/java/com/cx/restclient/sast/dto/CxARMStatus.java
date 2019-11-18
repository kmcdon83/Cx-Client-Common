package com.cx.restclient.sast.dto;


import com.cx.restclient.dto.BaseStatus;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Created by Galn on 07/03/2018.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CxARMStatus extends BaseStatus {
    private CxID project;
    private CxID scan;
    String status;
    String lastSync;

    public CxID getProject() {
        return project;
    }

    public void setProject(CxID project) {
        this.project = project;
    }

    public CxID getScan() {
        return scan;
    }

    public void setScan(CxID scan) {
        this.scan = scan;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getLastSync() {
        return lastSync;
    }

    public void setLastSync(String lastSync) {
        this.lastSync = lastSync;
    }
}
