package com.cx.utility;

import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.util.Properties;

public final class TestingUtils {

    public static Properties getProps(String propsName, Class clazz) throws IOException {
        Properties properties = new Properties();
        ClassLoader classLoader = clazz.getClassLoader();
        URL resource = classLoader.getResource(propsName);
        properties.load(new FileReader(resource.getFile()));

        return properties;
    }
}
