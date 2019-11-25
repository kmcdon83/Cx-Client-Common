package com.cx.restclient.connection;

import com.cx.restclient.CxShragaClient;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.osa.dto.OSAResults;
import com.cx.restclient.sast.dto.SASTResults;
import com.cx.utility.TestingUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
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
    public void runOsaScan() throws MalformedURLException {
        CxScanConfig config = initOsaConfig();
        client = new CxShragaClient(config, log);
        try {
            client.init();
            client.createOSAScan();
            client.waitForOSAResults();
            final OSAResults latestOSAResults = client.getLatestOSAResults();
            Assert.assertNotNull(latestOSAResults.getOsaScanId(), "Expected valid osa scan id");
        } catch (IOException | CxClientException | InterruptedException e) {
            e.printStackTrace();
            log.error("Error running  osa scan: " + e.getMessage());
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void runSastScan() throws MalformedURLException {
        CxScanConfig config = initSastConfig();
        client = new CxShragaClient(config, log);
        try {
            client.init();
            client.createSASTScan();
            client.waitForSASTResults();
            final SASTResults latestSASTResults = client.getLatestSASTResults();
            Assert.assertNotNull(String.valueOf(latestSASTResults.getScanId()), "Expected valid osa scan id");
        } catch (IOException | CxClientException | InterruptedException e) {
            e.printStackTrace();
            log.error("Error running sast scan: " + e.getMessage());
            Assert.fail(e.getMessage());
        }
    }


    private CxScanConfig initSastConfig() {
        CxScanConfig config = new CxScanConfig();
        config.setSastEnabled(true);
        config.setReportsDir(new File("C:\\report"));
        config.setSourceDir(props.getProperty("sastSource"));
        config.setUsername(props.getProperty("user"));
        config.setPassword(props.getProperty("password"));
        config.setUrl(props.getProperty("serverUrl"));
        config.setCxOrigin("common");
        config.setProjectName("sastOnlyScan");
        config.setPresetName("Default");
        config.setTeamPath("\\CxServer");
        config.setSynchronous(true);
        config.setGeneratePDFReport(true);
        config.setOsaEnabled(false);
        config.setPresetName("Default");
//        config.setPresetId(7);

        return config;
    }

    private CxScanConfig initOsaConfig() {
        CxScanConfig config = new CxScanConfig();
        config.setSastEnabled(false);
        config.setSourceDir("C:\\sources\\osa\\HighVul");
        config.setReportsDir(new File("C:\\report"));
        config.setUsername("admin1");
        config.setPassword("Cx123456!");

        config.setUrl("http://10.32.1.57");
        config.setCxOrigin("common");
        config.setProjectName("osaOnlyScan");
        config.setPresetName("Default");
        config.setTeamPath("\\CxServer");
        config.setSynchronous(true);
        config.setGeneratePDFReport(true);
        config.setOsaEnabled(true);

        config.setOsaRunInstall(true);
        config.setOsaThresholdsEnabled(true);
        config.setPublic(true);

        return config;
    }

}
