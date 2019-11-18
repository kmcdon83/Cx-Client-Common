package com.cx.restclient.cxArm.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Created by Galn on 7/11/2018.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CxArmConfig {

    private String webServer;
    private boolean isOsaEulaAccepted;
    private String cxARMPolicyURL;
    private boolean isConfidenceLevelColumnOptional;
    private String osA_REQUEST_SAMPLING_INTERVAL_SECONDS;

    public String getWebServer() {
        return webServer;
    }

    public void setWebServer(String webServer) {
        this.webServer = webServer;
    }

    public boolean getIsOsaEulaAccepted() {
        return isOsaEulaAccepted;
    }

    public void setIsOsaEulaAccepted(boolean osaEulaAccepted) {
        isOsaEulaAccepted = osaEulaAccepted;
    }

    public String getCxARMPolicyURL() {
        return cxARMPolicyURL;
    }

    public void setCxARMPolicyURL(String cxARMPolicyURL) {
        this.cxARMPolicyURL = cxARMPolicyURL;
    }

    public boolean getIsConfidenceLevelColumnOptional() {
        return isConfidenceLevelColumnOptional;
    }

    public void setIsConfidenceLevelColumnOptional(boolean confidenceLevelColumnOptional) {
        isConfidenceLevelColumnOptional = confidenceLevelColumnOptional;
    }

    public String getOsA_REQUEST_SAMPLING_INTERVAL_SECONDS() {
        return osA_REQUEST_SAMPLING_INTERVAL_SECONDS;
    }

    public void setOsA_REQUEST_SAMPLING_INTERVAL_SECONDS(String osA_REQUEST_SAMPLING_INTERVAL_SECONDS) {
        this.osA_REQUEST_SAMPLING_INTERVAL_SECONDS = osA_REQUEST_SAMPLING_INTERVAL_SECONDS;
    }
}
