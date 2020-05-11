package com.cx.restclient.sca.dto;

import com.cx.restclient.sca.dto.report.Finding;
import com.cx.restclient.sca.dto.report.Package;
import com.cx.restclient.sca.dto.report.SCASummaryResults;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.List;

@Getter
@Setter
public class SCAResults implements Serializable {
    private String scanId;
    private SCASummaryResults summary;
    private String webReportLink;
    private List<Finding> findings;
    private List<Package> packages;
}
