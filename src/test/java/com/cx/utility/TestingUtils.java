package com.cx.utility;

import com.cx.restclient.sca.dto.SCAConfig;

import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.util.Properties;

public final class TestingUtils {

    public static Properties getProps(String propsName, Class<?> clazz) throws IOException {
        Properties properties = new Properties();
        ClassLoader classLoader = clazz.getClassLoader();
        URL resource = classLoader.getResource(propsName);
        if (resource == null) {
            throw new IOException(String.format("Resource '%s' is not found.", propsName));
        }
        properties.load(new FileReader(resource.getFile()));

        return properties;
    }

    public static SCAConfig getScaConfig(Properties props) {
        SCAConfig result = new SCAConfig();
        result.setApiUrl(props.getProperty("sca.apiUrl"));
        result.setAccessControlUrl(props.getProperty("sca.accessControlUrl"));
        result.setTenant(props.getProperty("sca.tenant"));
        result.setUsername(props.getProperty("sca.username"));
        result.setPassword(props.getProperty("sca.password"));
        result.setWebAppUrl(props.getProperty("sca.webAppUrl"));
        return result;
    }
}
