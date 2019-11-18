package com.cx.restclient.dto;

import com.cx.restclient.configuration.CxScanConfig;

/**
 * Created by Galn on 11/25/2018.
 */
public class RemoteSourceRequest {
    String url;
    int port;
    private byte[] privateKey;
    private String[] paths;
    private String userName;
    private String password;
    private RemoteSourceTypes type;
    private  transient String browseMode;
    ;

    public RemoteSourceRequest() {
    }

    public RemoteSourceRequest(CxScanConfig config) {
        this.userName = config.getRemoteSrcUser();
        this.password = config.getRemoteSrcPass();
        this.url = config.getRemoteSrcUrl();
        this.port = config.getRemoteSrcPort();
        this.privateKey = config.getRemoteSrcKeyFile();
        this.paths = config.getPaths();
        this.type = config.getRemoteType();
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String absoluteUrl) {
        this.url = absoluteUrl;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public String[] getPaths() {
        return paths;
    }

    public void setPaths(String[] paths) {
        this.paths = paths;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public RemoteSourceTypes getType() {
        return type;
    }

    public void setType(RemoteSourceTypes type) {
        this.type = type;
    }

    public String getBrowseMode() {
        return browseMode;
    }

    public void setBrowseMode(String browseMode) {
        this.browseMode = browseMode;
    }

}
