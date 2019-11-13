package com.cx.restclient;

import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.LoginSettings;
import com.cx.restclient.dto.SCAConfig;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.httpClient.CxHttpClient;
import com.cx.restclient.osa.dto.ClientType;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.MalformedURLException;

/**
 * SCA - Software Composition Analysis - is the successor of OSA.
 */
class SCAClient {
    private final Logger log;
    private final SCAConfig scaConfig;

    // This class uses its own instance of CxHttpClient, because SCA has a different base URL and Access Control server.
    private final CxHttpClient httpClient;

    SCAClient(Logger log, CxScanConfig scanConfig) throws MalformedURLException {
        this.log = log;

        scaConfig = scanConfig.getScaConfig();
        httpClient = new CxHttpClient(scaConfig.getApiUrl(),
                scanConfig.getCxOrigin(),
                scanConfig.isDisableCertificateValidation(),
                scanConfig.isUseSSOLogin(),
                log);
    }

    void login() throws IOException, CxClientException {
        log.info("Logging into SCA.");
        LoginSettings settings = new LoginSettings();
        settings.setAccessControlBaseUrl(scaConfig.getAccessControlUrl());
        settings.setUsername(scaConfig.getUsername());
        settings.setPassword(scaConfig.getPassword());
        settings.setTenant(scaConfig.getTenant());
        settings.setClientTypeForPasswordAuth(ClientType.SCA_CLI);
        httpClient.login(settings);
    }
}
