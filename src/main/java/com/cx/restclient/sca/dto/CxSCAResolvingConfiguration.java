package com.cx.restclient.sca.dto;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class CxSCAResolvingConfiguration implements Serializable {
    List<String> Manifests = new ArrayList<>();
    List<String> Fingerprints = new ArrayList<>();

    public String getManifestsIncludePattern(){
        return StringUtils.joinWith(",", Manifests);
    }

    public String getFingerprintsIncludePattern(){
        return StringUtils.joinWith(",", Fingerprints);
    }
}
