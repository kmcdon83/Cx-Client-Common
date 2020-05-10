package com.cx.restclient.sca.dto.report;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class Package implements Serializable {
    public String id;
    public String name;
    public String version;
    public List<String> licenses = new ArrayList<>();
    public String matchType;
    public Integer highVulnerabilityCount;
    public Integer mediumVulnerabilityCount;
    public Integer lowVulnerabilityCount;
    public Integer ignoredVulnerabilityCount;
    public Integer numberOfVersionsSinceLastUpdate;
    public Object newestVersionReleaseDate;
    public Object newestVersion;
    public Boolean outdated;
    public String releaseDate;
    public String confidenceLevel;
    public Double riskScore;
    public String severity;
    public List<String> locations = new ArrayList<>();
    public List<Object> dependencyPaths = new ArrayList<>();
    public Object packageRepository;
    public Boolean isDirectDependency;
    public Boolean isDevelopment;
    public PackageUsage packageUsage;
}
