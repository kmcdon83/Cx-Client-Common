package com.cx.restclient.sca.dto;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class HandlerRef {
    private String type;
    private String value;
}
