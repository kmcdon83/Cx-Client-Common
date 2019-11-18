package com.cx.restclient.common;

import java.io.File;

/**
 * Created by Galn on 14/02/2018.
 */
public abstract class CxPARAM {
    public static final String AUTHENTICATION = "auth/identity/connect/token";
    public static final String ORIGIN_HEADER = "cxOrigin";
    public static final String CXPRESETS = "sast/presets";
    public static final String CXTEAMS = "auth/teams";
    public static final String CREATE_PROJECT = "projects";//Create new project (default preset and configuration)

    public static final String CX_REPORT_LOCATION = File.separator + "Checkmarx" + File.separator + "Reports";

    public static final String CX_ARM_URL ="/Configurations/Portal";
    public static final String CX_ARM_VIOLATION ="/cxarm/policymanager/projects/{projectId}/violations?provider={provider}";
    public static final String DENY_NEW_PROJECT_ERROR = "Creation of the new project [{projectName}] is not authorized. " +
            "Please use an existing project. \nYou can enable the creation of new projects by disabling" + "" +
            " the Deny new Checkmarx projects creation checkbox in the Checkmarx plugin global settings.\n";

}
