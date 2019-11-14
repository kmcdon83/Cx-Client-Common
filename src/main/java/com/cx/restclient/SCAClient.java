package com.cx.restclient;

import com.cx.restclient.common.UrlUtils;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.LoginSettings;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.httpClient.CxHttpClient;
import com.cx.restclient.httpClient.utils.ContentType;
import com.cx.restclient.httpClient.utils.HttpClientHelper;
import com.cx.restclient.osa.dto.ClientType;
import com.cx.restclient.sca.dto.CreateProjectRequest;
import com.cx.restclient.sca.dto.Project;
import com.cx.restclient.sca.dto.SCAConfig;
import org.apache.http.HttpStatus;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.List;

/**
 * SCA - Software Composition Analysis - is the successor of OSA.
 */
class SCAClient {
    private static final String API_PATH = "api/";

    private final Logger log;
    private final SCAConfig scaConfig;

    // This class uses its own instance of CxHttpClient, because SCA has a different base URL and Access Control server.
    private final CxHttpClient httpClient;

    private String projectId;

    SCAClient(Logger log, CxScanConfig scanConfig) throws MalformedURLException {
        this.log = log;

        scaConfig = scanConfig.getScaConfig();
        String apiBaseUrl = UrlUtils.parseURLToString(scaConfig.getApiUrl(), API_PATH);

        httpClient = new CxHttpClient(apiBaseUrl,
                scanConfig.getCxOrigin(),
                scanConfig.isDisableCertificateValidation(),
                scanConfig.isUseSSOLogin(),
                log);
    }

    void init() throws IOException, CxClientException {
        login();
        resolveProject();
    }

    private void resolveProject() throws IOException, CxClientException {
        projectId = getProjectIdByName(scaConfig.getProjectName());
        if (projectId == null) {
            log.debug("Project not found, creating a new one.");
            projectId = createProject(scaConfig.getProjectName());
        }
        log.debug("Using project ID: " + projectId);
    }

    void login() throws IOException, CxClientException {
        log.info("Logging into SCA.");
        LoginSettings settings = new LoginSettings();
        settings.setAccessControlBaseUrl(scaConfig.getAccessControlUrl());
        settings.setUsername(scaConfig.getUsername());
        settings.setPassword(scaConfig.getPassword());
        settings.setTenant(scaConfig.getTenant());
        settings.setClientTypeForPasswordAuth(ClientType.SCA_CLI);
        httpClient.login(settings);
    }

    private String getProjectIdByName(String name) throws IOException, CxClientException {
        log.debug("Getting project by name: " + name);

        List<Project> allProjects = (List<Project>) httpClient.getRequest("projects",
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                Project.class,
                HttpStatus.SC_OK,
                "SCA projects",
                true);

        String result = allProjects.stream()
                .filter((Project project) -> name.equals(project.getName()))
                .map(project -> project.getId())
                .findFirst()
                .orElse(null);

        return result;
    }

    private String createProject(String name) throws CxClientException, IOException {
        CreateProjectRequest request = new CreateProjectRequest();
        request.setName(name);

        StringEntity entity = HttpClientHelper.convertToStringEntity(request);

        Project newProject = httpClient.postRequest("projects",
                ContentType.CONTENT_TYPE_APPLICATION_JSON,
                entity,
                Project.class,
                HttpStatus.SC_CREATED,
                "create a project");

        return newProject.getId();
    }
}
