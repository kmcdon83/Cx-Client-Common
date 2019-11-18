package com.cx.restclient.cxArm.dto;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by Galn on 11/11/2018.
 */
public class Rule {
    List<Violation> violations = new ArrayList<Violation>();

    public List<Violation> getViolations() {
        return violations;
    }

    public void setViolations(List<Violation> violations) {
        this.violations = violations;
    }
}
