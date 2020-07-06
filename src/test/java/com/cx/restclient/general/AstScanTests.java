package com.cx.restclient.general;

import com.cx.restclient.ASTClient;
import com.cx.restclient.ast.dto.ASTConfig;
import com.cx.restclient.configuration.CxScanConfig;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Test;

@Slf4j
public class AstScanTests {
    @Test
    public void init() {
        ASTConfig astConfig = new ASTConfig();

        CxScanConfig config = new CxScanConfig();
        config.setAstConfig(astConfig);
        ASTClient client = new ASTClient(config, log);
        try {
            client.init();
        } catch (Exception e) {
            Assert.fail("Unexpected exception during init(): " + e);
        }
    }
}
