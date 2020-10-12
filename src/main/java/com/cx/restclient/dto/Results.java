package com.cx.restclient.dto;

import com.cx.restclient.exception.CxClientException;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public abstract class Results {
    private CxClientException exception;
}
