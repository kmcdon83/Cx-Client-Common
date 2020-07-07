package com.cx.restclient.ast.dto.sast;

import com.cx.restclient.dto.Results;
import com.cx.restclient.ast.dto.sca.report.ASTSummaryResults;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class ASTResults implements Serializable, Results {
    private String scanId;
    private ASTSummaryResults summary;
}
