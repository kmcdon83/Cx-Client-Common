package com.cx.restclient.sca.dto;

import java.time.OffsetDateTime;

public class SCASummaryResults {
    private String riskReportId;
    private int highVulnerabilitiesCount;
    private int mediumVulnerabilitiesCount;
    private int lowVulnerabilitiesCount;
    private int totalPackages;
    private int directPackages;
    private OffsetDateTime createdOn;
    private double riskScore;
    private int totalOutdatedPackages;

    public String getRiskReportId() {
        return riskReportId;
    }

    public void setRiskReportId(String riskReportId) {
        this.riskReportId = riskReportId;
    }

    public int getHighVulnerabilitiesCount() {
        return highVulnerabilitiesCount;
    }

    public void setHighVulnerabilitiesCount(int highVulnerabilitiesCount) {
        this.highVulnerabilitiesCount = highVulnerabilitiesCount;
    }

    public int getMediumVulnerabilitiesCount() {
        return mediumVulnerabilitiesCount;
    }

    public void setMediumVulnerabilitiesCount(int mediumVulnerabilitiesCount) {
        this.mediumVulnerabilitiesCount = mediumVulnerabilitiesCount;
    }

    public int getLowVulnerabilitiesCount() {
        return lowVulnerabilitiesCount;
    }

    public void setLowVulnerabilitiesCount(int lowVulnerabilitiesCount) {
        this.lowVulnerabilitiesCount = lowVulnerabilitiesCount;
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

    public OffsetDateTime getCreatedOn() {
        return createdOn;
    }

    public void setCreatedOn(OffsetDateTime createdOn) {
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
