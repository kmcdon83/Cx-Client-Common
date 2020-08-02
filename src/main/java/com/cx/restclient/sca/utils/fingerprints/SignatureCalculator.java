package com.cx.restclient.sca.utils.fingerprints;

import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.sca.utils.fingerprints.CxSCAFileSignature;

import java.io.IOException;


public interface SignatureCalculator {
    CxSCAFileSignature calculateSignature(byte[] content) throws IOException, CxClientException;

}
