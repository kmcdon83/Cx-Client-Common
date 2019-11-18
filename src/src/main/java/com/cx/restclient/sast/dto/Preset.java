package com.cx.restclient.sast.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Created by Galn on 14/02/2018.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Preset {
    public int id;
    public String name;

    public Preset() {
    }

    public Preset(int id, String name) {
        this.id = id;
        this.name = name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Preset)) return false;

        Preset preset = (Preset) o;

        if (getId() != preset.getId()) return false;
        return getName().equals(preset.getName());

    }

    @Override
    public int hashCode() {
        int result = getId();
        result = 31 * result + getName().hashCode();
        return result;
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
