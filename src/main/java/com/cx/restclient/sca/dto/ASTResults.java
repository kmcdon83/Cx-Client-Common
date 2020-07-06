package com.cx.restclient.sca.dto;

import com.cx.restclient.dto.Results;
import com.cx.restclient.sca.dto.report.ASTSummaryResults;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class ASTResults implements Serializable, Results {
    private String scanId;
    private ASTSummaryResults summary;
}
