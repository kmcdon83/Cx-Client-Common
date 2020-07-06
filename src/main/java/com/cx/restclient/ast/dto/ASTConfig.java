package com.cx.restclient.ast.dto;

import com.cx.restclient.dto.SourceLocationType;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class ASTConfig implements Serializable {
    private String apiBaseUrl;
    private SourceLocationType sourceLocationType;
}
