package com.cx.restclient.sca.dto;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class ScanStartHandler {
    /**
     * For local directory scan - the URL where the zipped directory has been uploaded.
     * For remote repo scan - a URL for which 'git clone' is possible.
     */
    private String url;
}
