package com.cx.restclient.sast.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Created by: dorg.
 * Date: 05/03/2018.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScanSettingResponse {

    private CxID project;
    private CxID preset;
    private CxID engineConfiguration;
    private CxID postScanAction;
    private EmailNotifications emailNotifications;

    public CxID getProject() {
        return project;
    }

    public void setProject(CxID project) {
        this.project = project;
    }

    public CxID getPreset() {
        return preset;
    }

    public void setPreset(CxID preset) {
        this.preset = preset;
    }

    public CxID getEngineConfiguration() {
        return engineConfiguration;
    }

    public void setEngineConfiguration(CxID engineConfiguration) {
        this.engineConfiguration = engineConfiguration;
    }

    public CxID getPostScanAction() {
        return postScanAction;
    }

    public void setPostScanAction(CxID postScanAction) {
        this.postScanAction = postScanAction;
    }

    public EmailNotifications getEmailNotifications() {
        return emailNotifications;
    }

    public void setEmailNotifications(EmailNotifications emailNotifications) {
        this.emailNotifications = emailNotifications;
    }
}
