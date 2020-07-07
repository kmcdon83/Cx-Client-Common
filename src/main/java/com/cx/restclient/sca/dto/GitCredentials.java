package com.cx.restclient.sca.dto;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class GitCredentials {
    private String type;
    private String value;
}
