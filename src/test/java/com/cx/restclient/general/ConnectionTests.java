package com.cx.restclient.general;

import com.cx.restclient.CxShragaClient;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.exception.CxClientException;
import com.cx.utility.TestingUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class ConnectionTests extends CommonClientTest {

    @Test
    public void ssoConnectionTest() {
        CxScanConfig config = initConfig();
        try {
            CxShragaClient client = new CxShragaClient(config, log);
            client.init();
        } catch (IOException | CxClientException e) {
            e.printStackTrace();
            log.error("Error running  osa scan: " + e.getMessage());
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void scaConnectionTest() {
        CxScanConfig config = new CxScanConfig();
        config.setCxOrigin("common");
        config.setScaConfig(TestingUtils.getScaConfig(props));
        try {
            CxShragaClient.testScaConnection(config, log);
        } catch (CxClientException e) {
            failOnException(e);
        }
    }

    private CxScanConfig initConfig() {
        CxScanConfig config = new CxScanConfig();
        config.setSastEnabled(true);
        config.setUseSSOLogin(true);
        config.setUsername(props.getProperty("username"));
        config.setPassword(props.getProperty("password"));
        config.setUrl(props.getProperty("serverUrl"));
        config.setCxOrigin("common");

        return config;
    }


}
