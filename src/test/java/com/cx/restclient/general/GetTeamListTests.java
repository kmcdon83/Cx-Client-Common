package com.cx.restclient.general;

import com.cx.restclient.CxShragaClient;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.Team;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

public class GetTeamListTests extends CommonClientTest {
    @Test
    public void getTeamListTest() {
        CxScanConfig config = initConfig();
        try {
            CxShragaClient client = new CxShragaClient(config, log);
            client.login("9.0");
            List<Team> teams = client.getTeamList();
            Assert.assertNotNull(teams);
            Assert.assertFalse(teams.isEmpty());
        } catch (Exception e) {
            failOnException(e);
        }
    }

    private CxScanConfig initConfig() {
        CxScanConfig config = new CxScanConfig();
        config.setUsername(props.getProperty("username"));
        config.setPassword(props.getProperty("password"));
        config.setUrl(props.getProperty("serverUrl"));
        config.setCxOrigin("common");
        return config;
    }
}
