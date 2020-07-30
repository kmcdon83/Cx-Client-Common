package com.cx.restclient.sca.utils;

import com.cx.restclient.exception.CxClientException;

import java.io.IOException;
import java.io.InputStream;

public interface SignatureCalculator {
    CxSCAFileSignature calculateSignature(InputStream inputStream) throws IOException, CxClientException;

}
