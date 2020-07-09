package com.cx.restclient.ast.dto.common;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.net.URL;

/**
 * Instructs AST scanners which repository should be scanned.
 * In the future this class may be expanded to include repo credentials and commit/branch/tag reference.
 */
@Getter
@Setter
public class RemoteRepositoryInfo implements Serializable {
    /**
     * A URL for which 'git clone' is possible.
     */
    private URL url;

    private String branch;

    private String username;

    private String password;
}
