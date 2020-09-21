package com.cx.restclient.dto.scansummary;

import javax.xml.bind.annotation.XmlType;

@XmlType(name="scanSummarySeverity")
public enum Severity {
    LOW,
    MEDIUM,
    HIGH
}
