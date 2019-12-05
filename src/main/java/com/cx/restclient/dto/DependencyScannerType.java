package com.cx.restclient.dto;

public enum DependencyScannerType {
    /**
     * Indicates that dependency scan should not be performed.
     */
    NONE("None"),

    OSA("CxOSA"),
    SCA("SCA");

    private final String displayName;

    DependencyScannerType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
