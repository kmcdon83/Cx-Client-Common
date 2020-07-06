package com.cx.restclient.ast.dto;

import lombok.Builder;

import java.util.ArrayList;
import java.util.List;

@Builder
public class StartScanRequest {
    public String scanID;
    public Project project;

    @Builder.Default
    public List<Config> config = new ArrayList<>();
}
