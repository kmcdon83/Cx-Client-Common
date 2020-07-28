package com.cx.restclient.sca;

public class SCAScanFingerprints {
    private String version;
    private SCAFingerprints[] fingerprints;


    public SCAScanFingerprints(String version, SCAFingerprints[] fingerprints) {
        this.version = version;
        this.fingerprints = fingerprints;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public SCAFingerprints[] getFingerprints() {
        return fingerprints;
    }

    public void setFingerprints(SCAFingerprints[] fingerprints) {
        this.fingerprints = fingerprints;
    }
}
