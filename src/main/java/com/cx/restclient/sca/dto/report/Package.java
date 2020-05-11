package com.cx.restclient.sca.dto.report;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Info about a package that SCA retrieves by analyzing project dependencies.
 */
@Getter
@Setter
public class Package implements Serializable {
    public String id;
    public String name;
    public String version;
    public List<String> licenses = new ArrayList<>();
    public String matchType;                            // enum values besides 'Filename'?
    public int highVulnerabilityCount;
    public int mediumVulnerabilityCount;
    public int lowVulnerabilityCount;
    public int ignoredVulnerabilityCount;
    public int numberOfVersionsSinceLastUpdate;
    public String newestVersionReleaseDate;
    public String newestVersion;
    public boolean outdated;
    public String releaseDate;
    public String confidenceLevel;
    public double riskScore;
    public String severity;                             // other values besides NONE,MEDIUM, HIGH - ?
    public List<String> locations = new ArrayList<>();
    public List<DependencyPath> dependencyPaths = new ArrayList<>();
    public String packageRepository;
    public boolean isDirectDependency;
    public boolean isDevelopment;
    public PackageUsage packageUsage;
}
