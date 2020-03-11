package com.cx.restclient.sast.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.Date;

@JsonIgnoreProperties(ignoreUnknown = true)
public class DateAndTime {
    private Date startedOn;
    private Date finishedOn;
    private Date engineStartedOn;
    private Date engineFinishedOn;

    public DateAndTime() {
    }

    public Date getStartedOn() {
        return startedOn;
    }

    public void setStartedOn(Date startedOn) {
        this.startedOn = startedOn;
    }

    public Date getFinishedOn() {
        return finishedOn;
    }

    public void setFinishedOn(Date finishedOn) {
        this.finishedOn = finishedOn;
    }

    public Date getEngineStartedOn() {
        return engineStartedOn;
    }

    public void setEngineStartedOn(Date engineStartedOn) {
        this.engineStartedOn = engineStartedOn;
    }

    public Date getEngineFinishedOn() {
        return engineFinishedOn;
    }

    public void setEngineFinishedOn(Date engineFinishedOn) {
        this.engineFinishedOn = engineFinishedOn;
    }
}
