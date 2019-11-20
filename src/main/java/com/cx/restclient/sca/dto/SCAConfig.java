package com.cx.restclient.sca.dto;

import java.io.Serializable;

public class SCAConfig implements Serializable {
    private String apiUrl;
    private String accessControlUrl;
    private String username;
    private String password;
    private String tenant;

    public String getApiUrl() {
        return apiUrl;
    }

    public void setApiUrl(String apiUrl) {
        this.apiUrl = apiUrl;
    }

    public void setAccessControlUrl(String accessControlUrl) {
        this.accessControlUrl = accessControlUrl;
    }

    public String getAccessControlUrl() {
        return accessControlUrl;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public void setTenant(String tenant) {
        this.tenant = tenant;
    }

    public String getTenant() {
        return tenant;
    }
}
