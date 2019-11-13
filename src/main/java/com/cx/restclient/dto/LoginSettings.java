package com.cx.restclient.dto;

import com.cx.restclient.osa.dto.ClientType;

public class LoginSettings {
    private String accessControlBaseUrl;
    private String username;
    private String password;
    private CharSequence tenant;
    private String refreshToken;

    // TODO: find a way to use a single client type here.
    private ClientType clientTypeForRefreshToken;
    private ClientType clientTypeForPasswordAuth;

    public void setAccessControlBaseUrl(String accessControlBaseUrl) {
        this.accessControlBaseUrl = accessControlBaseUrl;
    }

    public String getAccessControlBaseUrl() {
        return accessControlBaseUrl;
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

    public void setClientTypeForRefreshToken(ClientType clientType) {
        this.clientTypeForRefreshToken = clientType;
    }

    public ClientType getClientTypeForRefreshToken() {
        return clientTypeForRefreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setClientTypeForPasswordAuth(ClientType clientType) {
        this.clientTypeForPasswordAuth = clientType;
    }

    public ClientType getClientTypeForPasswordAuth() {
        return clientTypeForPasswordAuth;
    }

    public CharSequence getTenant() {
        return tenant;
    }

    public void setTenant(CharSequence tenant) {
        this.tenant = tenant;
    }
}
