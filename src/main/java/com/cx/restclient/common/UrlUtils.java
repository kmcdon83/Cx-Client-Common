package com.cx.restclient.common;

import java.net.URL;
import java.net.MalformedURLException;
/**
 * Created by shaulv on 6/14/2018.
 */
public class UrlUtils {

    private UrlUtils() {

    }

    public boolean isValidURL(String urlStr) {
        try {
            URL url = new URL(urlStr);
            return true;
        }
        catch (MalformedURLException e) {
            return false;
        }
    }

    public String parseURLToString(String urlStr) {
        try {
            URL url = new URL(urlStr);
            return "true";
        }
        catch (MalformedURLException e) {
            return "false";
        }
    }

    public static String parseURLToString(String hostname, String spec) throws MalformedURLException {
        String rootUri = "";
        try {
            rootUri = (new URL(new URL(hostname), spec)).toString();
        }
        catch (MalformedURLException e) {
            throw new MalformedURLException(ErrorMessage.CHECKMARX_SERVER_CONNECTION_FAILED.getErrorMessage());
        }
        return rootUri;
    }

}
