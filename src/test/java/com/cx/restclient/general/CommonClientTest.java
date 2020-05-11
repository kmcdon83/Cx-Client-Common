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
    private static final String MAIN_PROPERTIES_FILE = "config.properties";
    public static final String OVERRIDE_FILE = "config-secrets.properties";

    static Properties props;

    @BeforeClass
    public static void initTest() throws IOException {
        props = TestingUtils.getProps(MAIN_PROPERTIES_FILE, CommonClientTest.class);
        loadOverrides(props);
    }

    private static void loadOverrides(Properties targetProps) {
        try {
            Properties overridingProps = TestingUtils.getProps(OVERRIDE_FILE, CommonClientTest.class);
            targetProps.putAll(overridingProps);
        } catch (IOException e) {
            log.warn("Failed to load property overrides.");
        }
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
