package com.cx.restclient.sca.dto;

public class SCAResults {
    private String scanId;
    private SCASummaryResults summary;
    private String webReportLink;

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

    public void setWebReportLink(String webReportLink) {
        this.webReportLink = webReportLink;
    }

    public String getWebReportLink() {
        return webReportLink;
    }
}
