package com.cx.restclient.ast.dto.common;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Builder
@Getter
public class StartScanRequest {
    private ProjectToScan project;
    private List<ScanConfig> config;
}
