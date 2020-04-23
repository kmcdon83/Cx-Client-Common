package com.cx.restclient.general;

import com.cx.restclient.CxShragaClient;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.DependencyScanResults;
import com.cx.restclient.dto.DependencyScannerType;
import com.cx.restclient.dto.ProxyConfig;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.sca.dto.SCAConfig;
import com.cx.restclient.sca.dto.SCAResults;
import com.cx.utility.TestingUtils;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.net.MalformedURLException;

@Ignore
public class ScaScanTests extends CommonClientTest {
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
