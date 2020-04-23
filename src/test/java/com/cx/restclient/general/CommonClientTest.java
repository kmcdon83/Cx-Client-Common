package com.cx.restclient.general;

import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.ProxyConfig;
import com.cx.utility.TestingUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Properties;

public abstract class CommonClientTest {
    private static final String PROPERTIES_FILE = "config.properties";
    Logger log = LoggerFactory.getLogger(ConnectionTests.class.getName());
    static Properties props;

    @BeforeClass
    public static void initTest() throws IOException {
        props = TestingUtils.getProps(PROPERTIES_FILE, ProjectScanTests.class);
    }

    protected static void setProxy(CxScanConfig config) {
        ProxyConfig proxyConfig = new ProxyConfig();
        proxyConfig.setHost(props.getProperty("proxy.host"));
        proxyConfig.setPort(Integer.parseInt(props.getProperty("proxy.port")));
        config.setProxyConfig(proxyConfig);
    }

    void failOnException(Exception e) {
        log.error("Unexpected exception.", e);
        Assert.fail(e.getMessage());
    }
}
