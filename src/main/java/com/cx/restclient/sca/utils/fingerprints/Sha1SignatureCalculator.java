package com.cx.restclient.sca.utils.fingerprints;

import com.cx.restclient.exception.CxClientException;
import org.apache.commons.codec.binary.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha1SignatureCalculator implements SignatureCalculator {


    private static final String SHA1_SIGNATURE_TYPE_NAME = "SHA1";

    @Override
    public CxSCAFileSignature calculateSignature(byte[] content) throws CxClientException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new CxClientException("Unable to use SHA-1 algorithm", e);
        }

        digest.update(content);

        return new CxSCAFileSignature(SHA1_SIGNATURE_TYPE_NAME, Hex.encodeHexString(digest.digest()));
    }

}
