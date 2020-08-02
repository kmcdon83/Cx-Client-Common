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

    public static SCAConfig getScaConfig(Properties props, boolean useOnPremiseAuthentication, boolean includeSource) {
        String accessControlProp, usernameProp, passwordProp;
        if (useOnPremiseAuthentication) {
            accessControlProp = "sca.onPremise.accessControlUrl";
            usernameProp = "sca.onPremise.username";
            passwordProp = "sca.onPremise.password";
        } else {
            accessControlProp = "sca.cloud.accessControlUrl";
            usernameProp = "sca.cloud.username";
            passwordProp = "sca.cloud.password";
        }

        SCAConfig result = new SCAConfig();
        result.setApiUrl(props.getProperty("sca.apiUrl"));
        result.setWebAppUrl(props.getProperty("sca.webAppUrl"));
        result.setTenant(props.getProperty("sca.tenant"));
        result.setAccessControlUrl(props.getProperty(accessControlProp));
        result.setUsername(props.getProperty(usernameProp));
        result.setPassword(props.getProperty(passwordProp));
        result.setIncludeSources(includeSource);
        return result;
    }

    public static SCAConfig getScaConfig(Properties props, boolean useOnPremiseAuthentication) {
        return getScaConfig(props, useOnPremiseAuthentication, false);
    }
}
