package com.cx.restclient.sca.dto;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.net.URL;

@Getter
@Setter
public class RemoteRepositoryInfo implements Serializable {
    /**
     * A URL for which 'git pull' is possible.
     */
    private URL url;
}
