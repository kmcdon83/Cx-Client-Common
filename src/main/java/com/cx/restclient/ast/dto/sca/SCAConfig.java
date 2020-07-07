package com.cx.restclient.ast.dto.sca;

import com.cx.restclient.ast.dto.sast.ASTConfig;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class SCAConfig extends ASTConfig implements Serializable {
    private String accessControlUrl;
    private String username;
    private String password;
    private String tenant;
    private String webAppUrl;
}
