package com.cx.restclient.sca.dto;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class ProjectToScan {
    private String id;
    private String type;
    private ScanStartHandler handler;
}
