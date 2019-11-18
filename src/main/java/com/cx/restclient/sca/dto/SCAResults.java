package com.cx.restclient.sca.dto;

public class SCAResults {
    private String scanId;
    private SCASummaryResults summary;

    public void setScanId(String scanId) {
        this.scanId = scanId;
    }

    public String getScanId() {
        return scanId;
    }

    public void setSummary(SCASummaryResults summary) {
        this.summary = summary;
    }

    public SCASummaryResults getSummary() {
        return summary;
    }
}
