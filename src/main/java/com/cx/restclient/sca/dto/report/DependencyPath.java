package com.cx.restclient.sca.dto.report;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * Added for readability.
 */
@Getter
@Setter
public class DependencyPath extends ArrayList<DependencyPathElement> implements Serializable {
}
