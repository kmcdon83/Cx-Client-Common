package com.cx.restclient.osa.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CVEReportTableRow implements Serializable {

    private String name;
    private String severity;
    private String publishDate;
    private String libraryName;
    private String state;

    public CVEReportTableRow(String name, String severity, String publishDate, String libraryName, String state) {
        this.name = name;
        this.severity = severity;
        this.publishDate = publishDate;
        this.libraryName = libraryName;
        this.state = state;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getPublishDate() {
        return publishDate;
    }

    public void setPublishDate(String publishDate) {
        this.publishDate = publishDate;
    }

    public String getLibraryName() {
        return libraryName;
    }

    public void setLibraryName(String libraryName) {
        this.libraryName = libraryName;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }
}
