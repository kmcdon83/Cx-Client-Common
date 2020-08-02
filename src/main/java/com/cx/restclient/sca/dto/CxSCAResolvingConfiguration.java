package com.cx.restclient.sca.dto;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class CxSCAResolvingConfiguration implements Serializable {
    List<String> manifests = new ArrayList<>();
    List<String> Extensions = new ArrayList<>();
}
