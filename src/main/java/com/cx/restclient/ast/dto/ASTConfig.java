package com.cx.restclient.ast.dto;

import com.cx.restclient.dto.SourceLocationType;
import com.cx.restclient.sca.dto.RemoteRepositoryInfo;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.io.Serializable;

@Getter
@Setter
@NoArgsConstructor
@SuperBuilder
public abstract class ASTConfig implements Serializable {
    private String apiUrl;
    private SourceLocationType sourceLocationType;
    private RemoteRepositoryInfo remoteRepositoryInfo;
}
