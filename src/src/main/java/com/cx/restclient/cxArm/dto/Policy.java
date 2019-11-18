package com.cx.restclient.cxArm.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Galn on 7/5/2018.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Policy implements Serializable {
    long policyId;
    String policyName;
     List<Violation> violations = new ArrayList<Violation>();

    public long getPolicyId() {
        return policyId;
    }

    public void setPolicyId(long policyId) {
        this.policyId = policyId;
    }

    public String getPolicyName() {
        return policyName;
    }

    public void setPolicyName(String policyName) {
        this.policyName = policyName;
    }

    public List<Violation> getViolations() {
        return violations;
    }

    public void setViolations(List<Violation> violations) {
        //Add the policy name to the violations for the report
            for(Violation violation: violations){
                violation.setPolicyName(policyName);
            }

        this.violations = violations;
    }
}
