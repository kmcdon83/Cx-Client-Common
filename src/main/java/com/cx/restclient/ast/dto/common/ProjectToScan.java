package com.cx.restclient.ast.dto.common;

import com.cx.restclient.ast.dto.common.ScanStartHandler;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class ProjectToScan {
    private String id;
    private String type;
    private ScanStartHandler handler;
}
