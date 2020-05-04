package com.cx.restclient.general;

import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.ProxyConfig;
import com.cx.utility.TestingUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.BeforeClass;

import java.io.IOException;
import java.util.Properties;

@Slf4j
public abstract class CommonClientTest {
    private static final String PROPERTIES_FILE = "config.properties";
    static Properties props;

    @BeforeClass
    public static void initTest() throws IOException {
        props = TestingUtils.getProps(PROPERTIES_FILE, SastScanTests.class);
    }

    protected static void setProxy(CxScanConfig config) {
        ProxyConfig proxyConfig = new ProxyConfig();
        proxyConfig.setHost(props.getProperty("proxy.host"));
        proxyConfig.setPort(Integer.parseInt(props.getProperty("proxy.port")));
        config.setProxyConfig(proxyConfig);
    }

    void failOnException(Exception e) {
        log.error("Unexpected exception during test.", e);
        Assert.fail(e.getMessage());
    }
}
