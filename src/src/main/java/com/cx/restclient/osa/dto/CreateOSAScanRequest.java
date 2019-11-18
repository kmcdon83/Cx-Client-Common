package com.cx.restclient.osa.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CreateOSAScanRequest {

    @JsonProperty("ProjectId")
    private long projectId;

    @JsonProperty("Content")
    private Content content;

    public CreateOSAScanRequest(long projectId, String content) {
        this.projectId = projectId;
        this.content = new Content(content);
    }

    public long getProjectId() {
        return projectId;
    }

    public void setProjectId(long projectId) {
        this.projectId = projectId;
    }

    public Content getContent() {
        return content;
    }

    public void setContent(Content content) {
        this.content = content;
    }
}
