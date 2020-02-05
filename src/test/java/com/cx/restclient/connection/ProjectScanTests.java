package com.cx.restclient.connection;

import com.cx.restclient.CxShragaClient;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.DependencyScanResults;
import com.cx.restclient.dto.DependencyScannerType;
import com.cx.restclient.dto.ProxyConfig;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.sast.dto.SASTResults;
import com.cx.restclient.sca.dto.SCAConfig;
import com.cx.restclient.sca.dto.SCAResults;
import com.cx.utility.TestingUtils;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.net.MalformedURLException;

@Ignore
public class ProjectScanTests extends CommonClientTest {
    @Test
    public void runOsaScan() throws MalformedURLException, CxClientException {
        CxScanConfig config = initOsaConfig();
        CxShragaClient client = new CxShragaClient(config, log);
        try {
            client.init();
            client.createDependencyScan();
            DependencyScanResults results = client.waitForDependencyScanResults();
            Assert.assertNotNull(results);
            Assert.assertNull(results.getScaResults());
            Assert.assertNotNull(results.getOsaResults());
            Assert.assertNotNull("Expected valid osa scan id", results.getOsaResults().getOsaScanId());
        } catch (Exception e) {
            failOnException(e);
        }
    }

    @Test
    public void runSastScan() throws MalformedURLException, CxClientException {
        CxScanConfig config = initSastConfig();
        runSastScan(config);
    }

    @Test
    public void runSastScanWithProxy() throws MalformedURLException, CxClientException {
        CxScanConfig config = initSastConfig();
        setProxy(config);
        runSastScan(config);
    }

    @Test
    public void runScaScan() throws MalformedURLException, CxClientException {
        CxScanConfig config = initScaConfig();
        runScaScan(config);
    }

    @Test
    public void runScaScanWithProxy() throws MalformedURLException, CxClientException {
        CxScanConfig config = initScaConfig();
        setProxy(config);
        runScaScan(config);
    }

    private void setProxy(CxScanConfig config) {
        ProxyConfig proxyConfig = new ProxyConfig();
        proxyConfig.setHost(props.getProperty("proxy.host"));
        proxyConfig.setPort(Integer.parseInt(props.getProperty("proxy.port")));
        config.setProxyConfig(proxyConfig);
    }

    private void runScaScan(CxScanConfig config) throws MalformedURLException, CxClientException {
        CxShragaClient client = new CxShragaClient(config, log);
        try {
            client.init();
            client.createDependencyScan();
            DependencyScanResults results = client.waitForDependencyScanResults();
            Assert.assertNotNull(results);
            Assert.assertNull(results.getOsaResults());

            SCAResults scaResults = results.getScaResults();
            Assert.assertNotNull(scaResults);
            Assert.assertNotNull(scaResults.getSummary());
            Assert.assertNotNull(scaResults.getScanId());
            Assert.assertNotNull(scaResults.getWebReportLink());
        } catch (Exception e) {
            failOnException(e);
        }
    }

    private void runSastScan(CxScanConfig config) throws MalformedURLException, CxClientException {
        CxShragaClient client = new CxShragaClient(config, log);
        try {
            client.init();
            client.createSASTScan();
            SASTResults results = client.waitForSASTResults();
            Assert.assertNotNull(results);
            Assert.assertNotEquals("Expected valid SAST scan id", 0, results.getScanId());
        } catch (Exception e) {
            failOnException(e);
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
        config.setDependencyScannerType(DependencyScannerType.SCA);
        config.setSastEnabled(false);
        config.setSourceDir(props.getProperty("dependencyScanSourceDir"));
        config.setOsaThresholdsEnabled(true);
        config.setProjectName("scaOnlyScan");

        SCAConfig sca = TestingUtils.getScaConfig(props);
        config.setScaConfig(sca);

        return config;
    }
}
