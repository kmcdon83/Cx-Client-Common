package com.cx.restclient.sca.dto.report;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class Finding implements Serializable {
    public String id;
    public String cveName;
    public Double score;
    public String severity;
    public String publishDate;
    public List<String> references = new ArrayList<>();
    public String description;
    public Object recommendations;
    public String packageId;
    public Object similarityId;
    public String fixResolutionText;
    public Boolean isIgnored;
}
