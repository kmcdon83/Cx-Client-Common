package com.cx.restclient.sca.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum SourceLocationType {
    LOCAL_DIRECTORY("upload"),
    REMOTE_REPOSITORY("git");

    private final String apiValue;
}
