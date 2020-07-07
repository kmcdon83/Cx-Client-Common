package com.cx.restclient.ast.dto.common;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class StartScanRequest {
    private ProjectToScan project;
}
