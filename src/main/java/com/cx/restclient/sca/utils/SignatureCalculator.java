package com.cx.restclient.sca.utils;

import com.cx.restclient.exception.CxClientException;

import java.io.IOException;


public interface SignatureCalculator {
    CxSCAFileSignature calculateSignature(byte[] content) throws IOException, CxClientException;

}
