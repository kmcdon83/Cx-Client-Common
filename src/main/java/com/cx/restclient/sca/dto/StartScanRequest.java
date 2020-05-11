package com.cx.restclient.sca.dto;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class StartScanRequest {
    private ProjectToScan project;
}
