package com.cx.restclient.cxArm.utils;

import com.cx.restclient.cxArm.dto.Policy;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.httpClient.CxHttpClient;

import java.io.IOException;
import java.util.List;

import static com.cx.restclient.common.CxPARAM.CX_ARM_VIOLATION;
import static com.cx.restclient.httpClient.utils.ContentType.CONTENT_TYPE_APPLICATION_JSON_V1;

/**
 * Created by Galn on 7/30/2018.
 */
public abstract class CxARMUtils {
    public static List<Policy> getProjectViolations(CxHttpClient httpClient, String cxARMUrl, long projectId, String provider) throws IOException, CxClientException {
        String relativePath = CX_ARM_VIOLATION.replace("{projectId}", Long.toString(projectId)).replace("{provider}", provider);
        return (List<Policy>) httpClient.getRequest(cxARMUrl, relativePath, CONTENT_TYPE_APPLICATION_JSON_V1, null, Policy.class, 200, "CxARM violations", true);
    }
}
