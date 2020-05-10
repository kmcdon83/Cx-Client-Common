package com.cx.restclient.sca.dto.report;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class PackageUsage implements Serializable {
    public String usageType;        // Enum values besides 'Used'?
    public Object packageId;        // Type?
    public List<Object> importsCalled = new ArrayList<>();  // List item type - ?
    public List<Object> methodsCalled = new ArrayList<>();  // List item type - ?
}
