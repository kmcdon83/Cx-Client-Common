package com.cx.restclient.connection;

import com.cx.restclient.CxShragaClient;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.DependencyScanResults;
import com.cx.restclient.dto.DependencyScannerType;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.sast.dto.SASTResults;
import com.cx.restclient.sca.dto.SCAConfig;
import com.cx.utility.TestingUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Properties;

@Ignore
public class ProjectScanTests {

    private static final String PROPERTIES_FILE = "config.properties";

    private Logger log = LoggerFactory.getLogger(ProjectScanTests.class.getName());
    private CxShragaClient client;
    private static Properties props;

    @BeforeClass
    public static void initTest() throws IOException {
        props = TestingUtils.getProps(PROPERTIES_FILE, ProjectScanTests.class);
    }

    @Test
    public void runOsaScan() throws MalformedURLException, CxClientException {
        CxScanConfig config = initOsaConfig();
        client = new CxShragaClient(config, log);
        try {
            client.init();
            client.createDependencyScan();
            client.waitForDependencyScanResults();
            final DependencyScanResults results = client.getLatestDependencyScanResults();
            Assert.assertNull(results.getScaResults());
            Assert.assertNotNull(results.getOsaResults());
            Assert.assertNotNull("Expected valid osa scan id", results.getOsaResults().getOsaScanId());
        } catch (IOException | CxClientException e) {
            e.printStackTrace();
            log.error("Error running  osa scan: " + e.getMessage());
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void runSastScan() throws MalformedURLException, CxClientException {
        CxScanConfig config = initSastConfig();
        client = new CxShragaClient(config, log);
        try {
            client.init();
            client.createSASTScan();
            client.waitForSASTResults();
            SASTResults latestSASTResults = client.getLatestSASTResults();
            Assert.assertNotEquals("Expected valid SAST scan id", 0, latestSASTResults.getScanId());
        } catch (IOException | CxClientException | InterruptedException e) {
            e.printStackTrace();
            log.error("Error running sast scan: " + e.getMessage());
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void runScaScan() throws MalformedURLException, CxClientException {
        CxScanConfig config = initScaConfig();
        client = new CxShragaClient(config, log);
        try {
            client.init();
            client.createDependencyScan();
            DependencyScanResults results = client.waitForDependencyScanResults();
            Assert.assertNotNull(results);
            Assert.assertNull(results.getOsaResults());
            Assert.assertNotNull(results.getScaResults());
            Assert.assertNotNull(results.getScaResults().getSummary());
            Assert.assertNotNull(results.getScaResults().getScanId());
        } catch (Exception e) {
            log.error("Error running SCA scan: " + e);
            Assert.fail(e.getMessage());
        }
    }

    private CxScanConfig initSastConfig() {
        CxScanConfig config = new CxScanConfig();
        config.setSastEnabled(true);
        config.setReportsDir(new File("C:\\report"));
        config.setSourceDir(props.getProperty("sastSource"));
        config.setUsername(props.getProperty("username"));
        config.setPassword(props.getProperty("password"));
        config.setUrl(props.getProperty("serverUrl"));
        config.setCxOrigin("common");
        config.setProjectName("sastOnlyScan");
        config.setPresetName("Default");
        config.setTeamPath("\\CxServer");
        config.setSynchronous(true);
        config.setGeneratePDFReport(true);
        config.setDependencyScannerType(DependencyScannerType.NONE);
        config.setPresetName("Default");
//        config.setPresetId(7);

        return config;
    }

    private CxScanConfig initOsaConfig() {
        CxScanConfig config = new CxScanConfig();
        config.setDependencyScannerType(DependencyScannerType.OSA);
        config.setSastEnabled(false);
        config.setSourceDir(props.getProperty("dependencyScanSourceDir"));
        config.setReportsDir(new File("C:\\report"));
        config.setUrl(props.getProperty("serverUrl"));
        config.setUsername(props.getProperty("username"));
        config.setPassword(props.getProperty("password"));

        config.setCxOrigin("common");
        config.setProjectName("osaOnlyScan");
        config.setPresetName("Default");
        config.setTeamPath("\\CxServer");
        config.setSynchronous(true);
        config.setGeneratePDFReport(true);

        config.setOsaRunInstall(true);
        config.setOsaThresholdsEnabled(true);
        config.setPublic(true);

        return config;
    }

    private CxScanConfig initScaConfig() {
        CxScanConfig config = new CxScanConfig();
        config.setUrl(props.getProperty("serverUrl"));
        config.setUsername(props.getProperty("username"));
        config.setPassword(props.getProperty("password"));
        config.setDependencyScannerType(DependencyScannerType.SCA);
        config.setSastEnabled(false);
        config.setSourceDir(props.getProperty("dependencyScanSourceDir"));
        config.setOsaThresholdsEnabled(true);
        config.setProjectName("scaOnlyScan");
        config.setTeamPath("\\CxServer");

        // Disabling certificate validation, otherwise we'll get an error during SCA login.
        // TODO: fix HTTPS logic in CxHttpClient.
        config.setDisableCertificateValidation(true);

        SCAConfig sca = new SCAConfig();
        sca.setApiUrl("https://api.lumodev.com");
        sca.setAccessControlUrl("https://upgrade.dev-ac-checkmarx.com");
        sca.setTenant("Checkmarx");
        sca.setUsername(props.getProperty("sca.username"));
        sca.setPassword(props.getProperty("sca.password"));
        config.setScaConfig(sca);

        return config;
    }
}
