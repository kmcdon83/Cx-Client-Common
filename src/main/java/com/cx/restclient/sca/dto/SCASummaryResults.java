package com.cx.restclient.sca.dto;

import java.time.OffsetDateTime;

public class SCASummaryResults {
    private String riskReportId;
    private int highVulnerabilityCount;
    private int mediumVulnerabilityCount;
    private int lowVulnerabilityCount;
    private int totalPackages;
    private int directPackages;
    private String createdOn;
    private double riskScore;
    private int totalOutdatedPackages;

    public String getRiskReportId() {
        return riskReportId;
    }

    public void setRiskReportId(String riskReportId) {
        this.riskReportId = riskReportId;
    }

    public int getHighVulnerabilityCount() {
        return highVulnerabilityCount;
    }

    public void setHighVulnerabilityCount(int highVulnerabilityCount) {
        this.highVulnerabilityCount = highVulnerabilityCount;
    }

    public int getMediumVulnerabilityCount() {
        return mediumVulnerabilityCount;
    }

    public void setMediumVulnerabilityCount(int mediumVulnerabilityCount) {
        this.mediumVulnerabilityCount = mediumVulnerabilityCount;
    }

    public int getLowVulnerabilityCount() {
        return lowVulnerabilityCount;
    }

    public void setLowVulnerabilityCount(int lowVulnerabilityCount) {
        this.lowVulnerabilityCount = lowVulnerabilityCount;
    }

    public int getTotalPackages() {
        return totalPackages;
    }

    public void setTotalPackages(int totalPackages) {
        this.totalPackages = totalPackages;
    }

    public int getDirectPackages() {
        return directPackages;
    }

    public void setDirectPackages(int directPackages) {
        this.directPackages = directPackages;
    }

    public String getCreatedOn() {
        return createdOn;
    }

    public void setCreatedOn(String createdOn) {
        this.createdOn = createdOn;
    }

    public double getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(double riskScore) {
        this.riskScore = riskScore;
    }

    public int getTotalOutdatedPackages() {
        return totalOutdatedPackages;
    }

    public void setTotalOutdatedPackages(int totalOutdatedPackages) {
        this.totalOutdatedPackages = totalOutdatedPackages;
    }
}
