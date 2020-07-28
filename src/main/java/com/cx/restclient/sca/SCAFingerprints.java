package com.cx.restclient.sca;

public class SCAFingerprints {
    private String path;
    private long size;
    private SCAFileSignature[] sig;


    public SCAFingerprints(String path, long size, SCAFileSignature[] sig) {
        this.path = path;
        this.size = size;
        this.sig = sig;
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

    public SCAFileSignature[] getSig() {
        return sig;
    }

    public void setSig(SCAFileSignature[] sig) {
        this.sig = sig;
    }
}
