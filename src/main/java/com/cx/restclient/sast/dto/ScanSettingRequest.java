package com.cx.restclient.sast.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Created by Galn on 05/02/2018.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScanSettingRequest {
    private long projectId;
    private long presetId;
    private long engineConfigurationId;

    public long getProjectId() {
        return projectId;
    }

    public void setProjectId(long projectId) {
        this.projectId = projectId;
    }

    public long getPresetId() {
        return presetId;
    }

    public void setPresetId(long presetId) {
        this.presetId = presetId;
    }

    public long getEngineConfigurationId() {
        return engineConfigurationId;
    }

    public void setEngineConfigurationId(long engineConfigurationId) {
        this.engineConfigurationId = engineConfigurationId;
    }
}
