package com.cx.restclient.sca.utils;

import java.util.ArrayList;
import java.util.List;

public class SCAFileFingerprints {
    private String path;
    private long size;
    private List<SCAFileSignature> signatures = new ArrayList<>();


    public SCAFileFingerprints(String path, long size, List<SCAFileSignature> sig) {
        this.path = path;
        this.size = size;
        this.signatures = sig;
    }

    public SCAFileFingerprints(String path, long size) {
        this.path = path;
        this.size = size;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public long getSize() {
        return size;
    }

    public void setSize(long size) {
        this.size = size;
    }


    public List<SCAFileSignature> getSignatures() {
        return signatures;
    }

    public void setSignatures(List<SCAFileSignature> signatures) {
        this.signatures = signatures;
    }

    public void addFileSignature(SCAFileSignature signature){
        this.signatures.add(signature);
    }
}
