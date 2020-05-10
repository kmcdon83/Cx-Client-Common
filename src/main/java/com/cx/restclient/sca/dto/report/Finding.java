package com.cx.restclient.sca.dto.report;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * This entity is called vulnerability in SCA API, but here it is called Finding for consistency.
 * Indicates a specific type of vulnerability detected in a specific package.
 */
@Getter
@Setter
public class Finding implements Serializable {
    public String id;
    public String cveName;
    public double score;
    public String severity;         // other enum values besides 'Medium', 'High' - ?
    public String publishDate;
    public List<String> references = new ArrayList<>();
    public String description;
    public Object recommendations;  // always null. What is the field type?
    public String packageId;
    public Object similarityId;     // always null. What is the field type?
    public String fixResolutionText;
    public boolean isIgnored;
}
