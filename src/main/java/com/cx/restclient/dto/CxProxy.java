package com.cx.restclient.dto;

/**
 * Created by Galn on 4/2/2019.
 */
public class CxProxy {
    private Boolean useProxy;
    private String proxyHost;
    private Integer proxyPort;
    private String proxyScheme;


    public CxProxy(Boolean useProxy, String proxyHost, Integer proxyPort, String scheme) {
        this.useProxy = useProxy;
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.proxyScheme = scheme;
    }

    public CxProxy() {
    }

    public Boolean getUseProxy() {
        return useProxy;
    }

    public void setUseProxy(Boolean useProxy) {
        this.useProxy = useProxy;
    }

    public String getProxyHost() {
        return proxyHost;
    }

    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    public Integer getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(Integer proxyPort) {
        this.proxyPort = proxyPort;
    }

    public void setProxyPort(String proxyPort) {
        try {
            this.proxyPort = Integer.parseInt(proxyPort);
        }catch (Exception ex){}
    }

    public String getProxyScheme() {
        return proxyScheme;
    }

    public void setProxyScheme(String proxyScheme) {
        this.proxyScheme = proxyScheme;
    }
}
