package com.cx.restclient.ast.dto;

import lombok.Builder;

@Builder
public class Project {
    public String id;
    public String type;
    public Handler handler;
    public Tags tags;
}
