package com.cx.restclient.common;

import org.apache.http.HttpStatus;

import java.util.HashSet;
import java.util.Set;

/**
 * Created by shaulv on 6/20/2018.
 */
public class ErrorUtil {

    private ErrorUtil() {

    }

    private static Set<Integer> serverErrorCodes = new HashSet<>();

    static {
        serverErrorCodes.add(HttpStatus.SC_INTERNAL_SERVER_ERROR);
        serverErrorCodes.add(HttpStatus.SC_NOT_IMPLEMENTED);
        serverErrorCodes.add(HttpStatus.SC_BAD_GATEWAY);
        serverErrorCodes.add(HttpStatus.SC_SERVICE_UNAVAILABLE);
        serverErrorCodes.add(HttpStatus.SC_GATEWAY_TIMEOUT);
        serverErrorCodes.add(HttpStatus.SC_HTTP_VERSION_NOT_SUPPORTED);
        serverErrorCodes.add(HttpStatus.SC_INSUFFICIENT_STORAGE);
    }

    public static boolean isServerErrorCodes(int errorCodes) {
        if(serverErrorCodes.contains(errorCodes)) {
            return true;
        }
        return false;
    }
}
