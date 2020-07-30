package com.cx.restclient.sca.utils;

import com.cx.restclient.sca.utils.SCAFileFingerprints;

import java.util.ArrayList;
import java.util.List;

public class SCAScanFingerprints {

    private String version;
    private List<SCAFileFingerprints> fingerprints = new ArrayList<>();


    public SCAScanFingerprints(String version, List<SCAFileFingerprints> fingerprints) {
        this.version = version;
        this.fingerprints = fingerprints;
    }

    public SCAScanFingerprints(){
        version = "1.0.0";
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public List<SCAFileFingerprints> getFingerprints() {
        return fingerprints;
    }

    public void setFingerprints(List<SCAFileFingerprints> fingerprints) {
        this.fingerprints = fingerprints;
    }

    public void addFileFingerprints(SCAFileFingerprints fileFingerprints){
        fingerprints.add(fileFingerprints);
    }
}
