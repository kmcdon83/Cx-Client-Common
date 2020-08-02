package com.cx.restclient.general;
import com.cx.restclient.sca.utils.fingerprints.CxSCAFileSignature;
import com.cx.restclient.sca.utils.fingerprints.Sha1SignatureCalculator;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.util.Objects;

import static org.junit.Assert.*;

@Slf4j
public class FingerprintTests {

    public static final String JAR_SAMPLE_RESOURCE_NAME = "gson-2.2.2.jar";
    public static final String EXPECTED_JAR_SHA1 = "1f96456ca233dec780aa224bff076d8e8bca3908";


    @Test
    public void fingerprint_calculateFileSha1() throws IOException {
        Sha1SignatureCalculator calculator = new Sha1SignatureCalculator();
        CxSCAFileSignature fileSignature = calculator.calculateSignature(readResourceFile(JAR_SAMPLE_RESOURCE_NAME));
        assertEquals(String.format("Sha1 signature of file %s is unexpected", JAR_SAMPLE_RESOURCE_NAME), EXPECTED_JAR_SHA1, fileSignature.getValue());
    }


    private static byte[] readResourceFile(String fileName) throws IOException {
        log.info("Reading resource file content '{}'", fileName);
        return IOUtils.toByteArray(Objects.requireNonNull(Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream(fileName)));

    }

}
