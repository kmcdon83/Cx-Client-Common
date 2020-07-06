package com.cx.restclient.general;

import com.cx.restclient.AstSastClient;
import com.cx.restclient.ast.dto.AstSastConfig;
import com.cx.restclient.configuration.CxScanConfig;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Test;

@Slf4j
public class AstScanTests {
    @Test
    public void init() {
        AstSastConfig astConfig = new AstSastConfig();

        CxScanConfig config = new CxScanConfig();
        config.setAstConfig(astConfig);
        AstSastClient client = new AstSastClient(config, log);
        try {
            client.init();
        } catch (Exception e) {
            Assert.fail("Unexpected exception during init(): " + e);
        }
    }
}
