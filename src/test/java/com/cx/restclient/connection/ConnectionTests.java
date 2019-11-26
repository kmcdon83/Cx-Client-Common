package com.cx.restclient.connection;

import com.cx.restclient.CxShragaClient;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.osa.dto.OSAResults;
import com.cx.utility.TestingUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Properties;

public class ConnectionTests {

    private Logger log = LoggerFactory.getLogger(ConnectionTests.class.getName());
    private static final String PROPERTIES_FILE = "config.properties";
    private CxShragaClient client;
    private static Properties props;

    @BeforeClass
    public static void initTest() throws IOException {
        props = TestingUtils.getProps(PROPERTIES_FILE, ProjectScanTests.class);
    }

    @Test
    public void ssoConnectionTest() {
        CxScanConfig config = initConfig();
        try {
            client = new CxShragaClient(config, log);
            client.init();
        } catch (IOException | CxClientException e) {
            e.printStackTrace();
            log.error("Error running  osa scan: " + e.getMessage());
            Assert.fail(e.getMessage());
        }
    }

    private CxScanConfig initConfig() {
        CxScanConfig config = new CxScanConfig();
        config.setSastEnabled(true);
        config.setUseSSOLogin(true);
        config.setUsername(props.getProperty("user"));
        config.setPassword(props.getProperty("password"));
        config.setUrl(props.getProperty("serverUrl"));
        config.setCxOrigin("common");

        return config;
    }


}
