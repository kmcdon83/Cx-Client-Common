package com.cx.restclient.common;

/**
 * Created by shaulv on 8/9/2018.
 */
public enum CxGlobalMessage {

    PROJECT_POLICY_STATUS("Project policy status : %s"),
    PROJECT_POLICY_VIOLATED_STATUS("Project policy status : violated"),
    PROJECT_POLICY_COMPLAINT_STATUS("Project policy status : compliant");

    private String message;

    private CxGlobalMessage(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public String formatMessage(Object... args) {
        return String.format(message, args);
    }
}
