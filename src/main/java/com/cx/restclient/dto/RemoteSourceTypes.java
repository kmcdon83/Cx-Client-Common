package com.cx.restclient.dto;

/**
 * Created by: Galn.
 * Date: 25/11/2016.
 */
public enum RemoteSourceTypes {

    SHARED("shared"),
    SVN("svn"),
    GIT("git"),
    TFS("tfs"),
    PERFORCE("perforce");

    private String value;

    RemoteSourceTypes(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

}