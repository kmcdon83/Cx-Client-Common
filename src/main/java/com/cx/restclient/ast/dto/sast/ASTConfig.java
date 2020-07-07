package com.cx.restclient.ast.dto.sast;

import com.cx.restclient.dto.SourceLocationType;
import com.cx.restclient.ast.dto.common.RemoteRepositoryInfo;
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
