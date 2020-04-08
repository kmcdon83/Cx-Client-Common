package com.cx.restclient.dto;

public class EngineConfiguration {

    private int id;

    private String name;

    public EngineConfiguration() {
    }

    public EngineConfiguration(String name) {
        this.name = name;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
