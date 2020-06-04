package com.cx.restclient.sast.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ExcludeSettingsRequest {
    private String excludeFoldersPattern;
    private String excludeFilesPattern;

    public ExcludeSettingsRequest() {
    }

    public ExcludeSettingsRequest(String excludeFoldersPattern, String excludeFilesPattern) {
        this.excludeFoldersPattern = excludeFoldersPattern;
        this.excludeFilesPattern = excludeFilesPattern;
    }

    public String getExcludeFoldersPattern() {
        return excludeFoldersPattern;
    }

    public void setExcludeFoldersPattern(String excludeFoldersPattern) {
        this.excludeFoldersPattern = excludeFoldersPattern;
    }

    public String getExcludeFilesPattern() {
        return excludeFilesPattern;
    }

    public void setExcludeFilesPattern(String excludeFilesPattern) {
        this.excludeFilesPattern = excludeFilesPattern;
    }
}
