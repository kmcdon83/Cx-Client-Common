package com.cx.restclient.dto;

import com.cx.restclient.configuration.CxScanConfig;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Created by Galn on 11/25/2018.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties({ "type" })
public class RemoteSourceRequest {

    public class Credentials {
        private String userName;
        private String password;

        public Credentials(String userName, String password) {
            this.userName = userName;
            this.password = password;
        }

        public String getUserName() {
            return userName;
        }

        public void setUserName(String userName) {
            this.userName = userName;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

    public class Uri {
        private String absoluteUrl;
        private int port;

        public Uri(String absoluteUrl, int port) {
            this.absoluteUrl = absoluteUrl;
            this.port = port;
        }

        public String getAbsoluteUrl() {
            return absoluteUrl;
        }

        public void setAbsoluteUrl(String absoluteUrl) {
            this.absoluteUrl = absoluteUrl;
        }

        public int getPort() {
            return port;
        }

        public void setPort(int port) {
            this.port = port;
        }
    }

    private Credentials credentials;
    private Uri uri;
    private byte[] privateKey;
    private String[] paths;
    private RemoteSourceTypes type;
    private String browseMode;

    public RemoteSourceRequest() {
    }

    public RemoteSourceRequest(CxScanConfig config) {
        credentials = new Credentials(config.getRemoteSrcUser(), config.getRemoteSrcPass());
        uri = new Uri(config.getRemoteSrcUrl(), config.getRemoteSrcPort());
        privateKey = config.getRemoteSrcKeyFile() == null ? new byte[0] : config.getRemoteSrcKeyFile();
        paths = config.getPaths();
        type = config.getRemoteType();
    }

    public Credentials getCredentials() {
        return credentials;
    }

    public void setCredentials(Credentials credentials) {
        this.credentials = credentials;
    }

    public Uri getUri() {
        return uri;
    }

    public void setUri(Uri uri) {
        this.uri = uri;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public String[] getPaths() {
        return paths;
    }

    public void setPaths(String[] paths) {
        this.paths = paths;
    }

    public RemoteSourceTypes getType() {
        return type;
    }

    public void setType(RemoteSourceTypes type) {
        this.type = type;
    }

    public String getBrowseMode() {
        return browseMode;
    }

    public void setBrowseMode(String browseMode) {
        this.browseMode = browseMode;
    }
}
