package com.cx.restclient.sca.dto;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class SCAConfig implements Serializable {
    private String apiUrl;
    private String accessControlUrl;
    private String username;
    private String password;
    private String tenant;
    private String webAppUrl;
    private RemoteRepositoryInfo remoteRepositoryInfo;
    private SourceLocationType sourceLocationType;
    private boolean includeSources;
    private String FingerprintsIncludePattern;
    private String ManifestsIncludePattern;
    private String FingerprintFilePath;
    private String zipFilePath;
}
