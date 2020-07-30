package com.cx.restclient.sca.utils;

import com.cx.restclient.exception.CxClientException;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha1SignatureCalculator implements SignatureCalculator {

    public static final int BLOCK_SIZE = 8192;
    public static final String SHA1_SIGNATURE_TYPE_NAME = "SHA1";

    @Override
    public SCAFileSignature calculateSignature(InputStream inputStream) throws IOException, CxClientException {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new CxClientException("Unable to use SHA-1 algorithm", e);
        }

        int n = 0;
        byte[] buffer = new byte[BLOCK_SIZE];
        while (n != -1) {
            n = inputStream.read(buffer);
            if (n > 0) {
                digest.update(buffer, 0, n);
            }
        }
        return new SCAFileSignature(SHA1_SIGNATURE_TYPE_NAME, DigestUtils.sha1Hex(digest.digest()));
    }

}
