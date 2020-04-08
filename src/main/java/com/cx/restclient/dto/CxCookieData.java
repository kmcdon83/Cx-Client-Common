package com.cx.restclient.dto;

public class CxCookieData {

    private String name;
    private String value;
    private Boolean httpOnly;
    private Boolean secure;

    public CxCookieData(String name, String value, Boolean httpOnly, Boolean secure) {
        this.name = name;
        this.value = value;
        this.httpOnly = httpOnly;
        this.secure = secure;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Boolean isHttpOnly() {
        return httpOnly;
    }

    public Boolean isSecure() {
        return secure;
    }

    @Override
    public String toString() {
        return "name='" + name + '\'' +
                ", value='" + value + '\'' +
                ", httpOnly=" + httpOnly +
                ", secure=" + secure +
                '}';
    }
}
