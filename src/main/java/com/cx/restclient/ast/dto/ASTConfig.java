package com.cx.restclient.ast.dto;

import com.cx.restclient.dto.SourceLocationType;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ASTConfig {
    private String apiBaseUrl;
    private SourceLocationType sourceLocationType;
}
