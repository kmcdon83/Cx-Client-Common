package com.cx.restclient.httpClient;

import com.cx.restclient.common.ErrorMessage;
import com.cx.restclient.common.UrlUtils;
import com.cx.restclient.dto.TokenLoginResponse;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.exception.CxHTTPClientException;
import com.cx.restclient.exception.CxTokenExpiredException;
import com.cx.restclient.osa.dto.ClientType;
import com.google.gson.Gson;
import org.apache.http.*;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CookieStore;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.*;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.cookie.Cookie;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.auth.DigestSchemeFactory;
import org.apache.http.impl.auth.win.WindowsCredentialsProvider;
import org.apache.http.impl.auth.win.WindowsNTLMSchemeFactory;
import org.apache.http.impl.auth.win.WindowsNegotiateSchemeFactory;
import org.apache.http.impl.client.*;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.slf4j.Logger;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;

import static com.cx.restclient.common.CxPARAM.*;
import static com.cx.restclient.httpClient.utils.ContentType.CONTENT_TYPE_APPLICATION_JSON;
import static com.cx.restclient.httpClient.utils.HttpClientHelper.*;
import static org.apache.commons.lang3.StringUtils.isEmpty;


/**
 * Created by Galn on 05/02/2018.
 */
public class CxHttpClient {

    private static String HTTP_HOST = System.getProperty("http.proxyHost");
    private static String HTTP_PORT = System.getProperty("http.proxyPort");
    private static String HTTP_USERNAME = System.getProperty("http.proxyUser");
    private static String HTTP_PASSWORD = System.getProperty("http.proxyPassword");

    private static String HTTPS_HOST = System.getProperty("https.proxyHost");
    private static String HTTPS_PORT = System.getProperty("https.proxyPort");
    private static String HTTPS_USERNAME = System.getProperty("https.proxyUser");
    private static String HTTPS_PASSWORD = System.getProperty("https.proxyPassword");

    private static HttpClient apacheClient;

    private Logger log;
    private TokenLoginResponse token;
    private String rootUri;
    private final String username;
    private final String password;
    private final String refreshToken;
    private String cxOrigin;
    private Boolean useSSo;
    private String teamPath;
    private CookieStore cookieStore = new BasicCookieStore();

    public CxHttpClient(String hostname, String username, String password, String origin,
                        boolean disableSSLValidation, boolean isSSO, String refreshToken, Logger logi,
                        String proxyHost, int proxyPort, String proxyUser, String proxyPassword) throws MalformedURLException, CxClientException {
        this.log = logi;
        this.username = username;
        this.password = password;
        this.refreshToken = refreshToken;
        this.rootUri = UrlUtils.parseURLToString(hostname, "CxRestAPI/");
        this.cxOrigin = origin;
        this.useSSo = isSSO;
        //create httpclient
        HttpClientBuilder cb = HttpClients.custom();
        cb.setDefaultRequestConfig(RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build());
        setSSLTls("TLSv1.2", logi);
        if (disableSSLValidation) {
            try {
                cb.setSSLSocketFactory(getTrustAllSSLSocketFactory());
                cb.setConnectionManager(getHttpConnectionManager(true));
            } catch (CxClientException e) {
                logi.warn("Failed to disable certificate verification: " + e.getMessage());
            }
        } else {
            cb.setConnectionManager(getHttpConnectionManager(false));
        }
        cb.setConnectionManagerShared(true);

        if (proxyHost != null) {
            setCustomProxy(cb, proxyHost, proxyPort, proxyUser, proxyPassword, logi);
        } else {
            setProxy(cb, logi);
        }

        if (useSSo) {
            cb.setDefaultCredentialsProvider(new WindowsCredentialsProvider(new SystemDefaultCredentialsProvider()));
            cb.setDefaultCookieStore(cookieStore);
        } else {
            cb.setConnectionReuseStrategy(new NoConnectionReuseStrategy());
        }
        cb.setDefaultAuthSchemeRegistry(getAuthSchemeProviderRegistry());
        cb.useSystemProperties();
        apacheClient = cb.build();
    }

    public CxHttpClient(String hostname, String username, String password, String origin,
                        boolean disableSSLValidation, boolean isSSO, String refreshToken, Logger logi) throws MalformedURLException, CxClientException {
        this(hostname, username, password, origin, disableSSLValidation, isSSO, refreshToken, logi, null, 0, null, null);
    }

    private static void setCustomProxy(HttpClientBuilder cb, String proxyHost, int proxyPort, String proxyUser, String proxyPassword, Logger logi) {
        HttpHost proxy = null;
        if (!isEmpty(proxyHost)) {
            proxy = new HttpHost(proxyHost, proxyPort, "http");
            if (!isEmpty(proxyUser) && !isEmpty(proxyPassword)) {
                CredentialsProvider credsProvider = new BasicCredentialsProvider();
                credsProvider.setCredentials(new AuthScope(proxy), new UsernamePasswordCredentials(proxyUser, proxyPassword));
                cb.setDefaultCredentialsProvider(credsProvider);
            }
        }
        if (proxy != null) {
            logi.info("Setting proxy for Checkmarx http client");
            cb.setProxy(proxy);
            cb.setRoutePlanner(new DefaultProxyRoutePlanner(proxy));
            cb.setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy());
        }
    }

    private static void setProxy(HttpClientBuilder cb, Logger logi) {
        HttpHost proxyHost = null;
        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        if (!isEmpty(HTTPS_HOST) && !isEmpty(HTTPS_PORT)) {
            proxyHost = new HttpHost(HTTPS_HOST, Integer.parseInt(HTTPS_PORT), "https");
            if (!isEmpty(HTTPS_USERNAME) && !isEmpty(HTTPS_PASSWORD)) {
                credsProvider.setCredentials(new AuthScope(HTTPS_HOST, Integer.parseInt(HTTPS_PORT)), new UsernamePasswordCredentials(HTTPS_USERNAME, HTTPS_PASSWORD));
                cb.setDefaultCredentialsProvider(credsProvider);
            }
        } else if (!isEmpty(HTTP_HOST) && !isEmpty(HTTP_PORT)) {
            proxyHost = new HttpHost(HTTP_HOST, Integer.parseInt(HTTP_PORT), "http");
            if (!isEmpty(HTTP_USERNAME) && !isEmpty(HTTP_PASSWORD)) {
                credsProvider.setCredentials(new AuthScope(HTTP_HOST, Integer.parseInt(HTTP_PORT)), new UsernamePasswordCredentials(HTTP_USERNAME, HTTP_PASSWORD));
                cb.setDefaultCredentialsProvider(credsProvider);
            }
        }
        if (proxyHost != null) {
            logi.info("Setting proxy for Checkmarx http client");
            cb.setRoutePlanner(new DefaultProxyRoutePlanner(proxyHost));
            cb.setProxy(proxyHost);
            cb.setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy());
        }
    }

    private static SSLConnectionSocketFactory getTrustAllSSLSocketFactory() throws CxClientException {
        TrustStrategy acceptingTrustStrategy = new TrustAllStrategy();
        SSLContext sslContext;
        try {
            sslContext = SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            throw new CxClientException("Fail to set trust all certificate, 'SSLConnectionSocketFactory'", e);
        }
        return new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
    }

    private static PoolingHttpClientConnectionManager getHttpConnectionManager(boolean disableSSLValidation) throws CxClientException {
        ConnectionSocketFactory factory;
        if (disableSSLValidation) {
            factory = getTrustAllSSLSocketFactory();
        } else {
            factory = new SSLConnectionSocketFactory(SSLContexts.createDefault());
        }
        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("https", factory)
                .register("http", new PlainConnectionSocketFactory())
                .build();
        PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
        connManager.setMaxTotal(50);
        connManager.setDefaultMaxPerRoute(5);
        return connManager;
    }

    private static Registry<AuthSchemeProvider> getAuthSchemeProviderRegistry() {
        return RegistryBuilder.<AuthSchemeProvider>create()
                .register(AuthSchemes.DIGEST, new DigestSchemeFactory())
                .register(AuthSchemes.BASIC, new BasicSchemeFactory())
                .register(AuthSchemes.NTLM, new WindowsNTLMSchemeFactory(null))
                .register(AuthSchemes.SPNEGO, new WindowsNegotiateSchemeFactory(null))
                .build();
    }

    public void login() throws IOException, CxClientException {
        if (refreshToken != null) {
            token = getAccessTokenFromRefreshToken();
        } else if (useSSo) {
            token = ssoLogin();
        } else {
            token = generateToken();
        }
    }

    private TokenLoginResponse ssoLogin() throws CxClientException {
        HttpUriRequest request;
        HttpResponse response = null;
        final String BASE_URL = "/auth/identity/";

        RequestConfig requestConfig = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setAuthenticationEnabled(true)
                .setCookieSpec(CookieSpecs.STANDARD)
                .build();
        try {
            //Request1
            request = RequestBuilder.post()
                    .setUri(rootUri + SSO_AUTHENTICATION)
                    .setConfig(requestConfig)
                    .setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.toString())
                    .setEntity(generateSSOEntity())
                    .build();

            response = apacheClient.execute(request);

            //Request2
            String cookies = retrieveCookies();
            String redirectURL = response.getHeaders("Location")[0].getValue();
            request = RequestBuilder.get()
                    .setUri(rootUri + BASE_URL + redirectURL)
                    .setConfig(requestConfig)
                    .setHeader("Cookie", cookies)
                    .setHeader("Upgrade-Insecure-Requests", "1")
                    .build();
            response = apacheClient.execute(request);

            //Request3
            cookies = retrieveCookies();
            redirectURL = response.getHeaders("Location")[0].getValue();
            redirectURL = rootUri + redirectURL.replace("/CxRestAPI/", "");
            request = RequestBuilder.get()
                    .setUri(redirectURL)
                    .setConfig(requestConfig)
                    .setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.toString())
                    .setHeader("Cookie", cookies)
                    .build();
            response = apacheClient.execute(request);
            return extractToken(response);
        } catch (IOException e) {
            log.error("Fail to login with windows authentication: " + e.getMessage());
            throw new CxClientException("Fail to login with windows authentication: " + e.getMessage());
        }
    }

    private TokenLoginResponse extractToken(HttpResponse response) {
        String redirectURL = response.getHeaders("Location")[0].getValue();
        if (!redirectURL.contains("access_token")) {
            throw new CxClientException("Failed retrieving access token from server");
        }
        return new Gson().fromJson(urlToJson(redirectURL), TokenLoginResponse.class);
    }

    private String urlToJson(String url) {
        url = url.replaceAll("=", "\":\"");
        url = url.replaceAll("&", "\",\"");
        return "{\"" + url + "\"}";
    }

    private String retrieveCookies() {
        List<Cookie> cookieList = cookieStore.getCookies();
        String cookies = "";
        for (Cookie cookie : cookieList) {
            cookies += cookie.getName() + "=" + cookie.getValue() + ";";
        }

        return cookies;
    }

    public TokenLoginResponse generateToken() throws IOException, CxClientException {
        return generateToken(ClientType.RESOURCE_OWNER);
    }

    public TokenLoginResponse generateToken(ClientType clientType) throws IOException, CxClientException {
        UrlEncodedFormEntity requestEntity = generateUrlEncodedFormEntity(clientType);
        HttpPost post = new HttpPost(rootUri + AUTHENTICATION);
        try {
            return request(post, ContentType.APPLICATION_FORM_URLENCODED.toString(), requestEntity,
                    TokenLoginResponse.class, HttpStatus.SC_OK, "authenticate", false, false);
        } catch (CxClientException e) {
            if (!e.getMessage().contains("invalid_scope")) {
                throw new CxClientException(String.format("Failed to generate access token, failure error was: %s", e.getMessage()), e);
            }
            ClientType.RESOURCE_OWNER.setScopes("sast_rest_api");
            requestEntity = generateUrlEncodedFormEntity(ClientType.RESOURCE_OWNER);
            return request(post, ContentType.APPLICATION_FORM_URLENCODED.toString(), requestEntity,
                    TokenLoginResponse.class, HttpStatus.SC_OK, "authenticate", false, false);
        }
    }

    private TokenLoginResponse getAccessTokenFromRefreshToken() throws IOException, CxClientException {
        UrlEncodedFormEntity requestEntity = generateTokenFromRefreshEntity(ClientType.CLI);
        HttpPost post = new HttpPost(rootUri + AUTHENTICATION);
        try {
            return request(post, ContentType.APPLICATION_FORM_URLENCODED.toString(), requestEntity,
                    TokenLoginResponse.class, HttpStatus.SC_OK, "authenticate", false, false);
        } catch (CxClientException e) {
            throw new CxClientException(String.format("Failed to generate access token from refresh token failure error was: %s", e.getMessage()), e);
        }
    }

    public void revokeToken(String token) throws IOException, CxClientException {
        UrlEncodedFormEntity requestEntity = generateRevocationEntity(ClientType.CLI, token);
        HttpPost post = new HttpPost(rootUri + REVOCATION);
        try {
            request(post, ContentType.APPLICATION_FORM_URLENCODED.toString(), requestEntity,
                    String.class, HttpStatus.SC_OK, "revocation", false, false);
        } catch (CxClientException e) {
            throw new CxClientException(String.format("Token revocation failure error was: %s", e.getMessage()), e);
        }
    }

    private UrlEncodedFormEntity generateRevocationEntity(ClientType clientType, String token) throws UnsupportedEncodingException {
        List<NameValuePair> parameters = new ArrayList<>();
        parameters.add(new BasicNameValuePair("token_type_hint", "refresh_token"));
        parameters.add(new BasicNameValuePair("token", token));
        parameters.add(new BasicNameValuePair("client_id", clientType.getClientId()));
        parameters.add(new BasicNameValuePair("client_secret", clientType.getClientSecret()));

        return new UrlEncodedFormEntity(parameters, "utf-8");

    }

    private UrlEncodedFormEntity generateUrlEncodedFormEntity(ClientType clientType) throws UnsupportedEncodingException {
        List<BasicNameValuePair> parameters = new ArrayList<>();
        parameters.add(new BasicNameValuePair("username", username));
        parameters.add(new BasicNameValuePair("password", password));
        parameters.add(new BasicNameValuePair("grant_type", "password"));
        parameters.add(new BasicNameValuePair("scope", clientType.getScopes()));
        parameters.add(new BasicNameValuePair("client_id", clientType.getClientId()));
        parameters.add(new BasicNameValuePair("client_secret", clientType.getClientSecret()));

        return new UrlEncodedFormEntity(parameters, "utf-8");
    }

    private UrlEncodedFormEntity generateTokenFromRefreshEntity(ClientType clientType) throws UnsupportedEncodingException {
        List<BasicNameValuePair> parameters = new ArrayList<>();
        parameters.add(new BasicNameValuePair("grant_type", "refresh_token"));
        parameters.add(new BasicNameValuePair("client_id", clientType.getClientId()));
        parameters.add(new BasicNameValuePair("client_secret", clientType.getClientSecret()));
        parameters.add(new BasicNameValuePair("refresh_token", refreshToken));

        return new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8.name());
    }

    //GET REQUEST
    public <T> T getRequest(String relPath, String contentType, Class<T> responseType, int expectStatus, String failedMsg, boolean isCollection) throws IOException, CxClientException {
        return getRequest(rootUri, relPath, CONTENT_TYPE_APPLICATION_JSON, contentType, responseType, expectStatus, failedMsg, isCollection);
    }

    public <T> T getRequest(String rootURL, String relPath, String acceptHeader, String contentType, Class<T> responseType, int expectStatus, String failedMsg, boolean isCollection) throws IOException, CxClientException {
        HttpGet get = new HttpGet(rootURL + relPath);
        get.addHeader(HttpHeaders.ACCEPT, acceptHeader);
        return request(get, contentType, null, responseType, expectStatus, "get " + failedMsg, isCollection, true);
    }

    //POST REQUEST
    public <T> T postRequest(String relPath, String contentType, HttpEntity entity, Class<T> responseType, int expectStatus, String failedMsg) throws IOException, CxClientException {
        HttpPost post = new HttpPost(rootUri + relPath);
        return request(post, contentType, entity, responseType, expectStatus, failedMsg, false, true);
    }

    //PUT REQUEST
    public <T> T putRequest(String relPath, String contentType, HttpEntity entity, Class<T> responseType, int expectStatus, String failedMsg) throws IOException, CxClientException {
        HttpPut put = new HttpPut(rootUri + relPath);
        return request(put, contentType, entity, responseType, expectStatus, failedMsg, false, true);
    }

    //PATCH REQUEST
    public void patchRequest(String relPath, String contentType, HttpEntity entity, int expectStatus, String failedMsg) throws IOException, CxClientException {
        HttpPatch patch = new HttpPatch(rootUri + relPath);
        request(patch, contentType, entity, null, expectStatus, failedMsg, false, true);
    }
    public void setTeamPathHeader(String teamPath){
        this.teamPath = teamPath;
    }

    private <T> T request(HttpRequestBase httpMethod, String contentType, HttpEntity entity, Class<T> responseType, int expectStatus, String failedMsg, boolean isCollection, boolean retry) throws IOException, CxClientException {
        if (contentType != null) {
            httpMethod.addHeader("Content-type", contentType);
        }
        if (entity != null && httpMethod instanceof HttpEntityEnclosingRequestBase) { //Entity for Post methods
            ((HttpEntityEnclosingRequestBase) httpMethod).setEntity(entity);
        }
        HttpResponse response = null;
        int statusCode = 0;

        try {
            httpMethod.addHeader(ORIGIN_HEADER, cxOrigin);
            httpMethod.addHeader(TEAM_PATH, this.teamPath);
            log.debug("request setTeamPathHeader " + this.teamPath);
            if (token != null) {
                httpMethod.addHeader(HttpHeaders.AUTHORIZATION, token.getToken_type() + " " + token.getAccess_token());
            }

            response = apacheClient.execute(httpMethod);
            statusCode = response.getStatusLine().getStatusCode();

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) { //Token expired
                throw new CxTokenExpiredException(extractResponseBody(response));
            }

            validateResponse(response, expectStatus, "Failed to " + failedMsg);

            //extract response as object and return the link
            return convertToObject(response, responseType, isCollection);
        } catch (UnknownHostException e) {
            throw new CxHTTPClientException(ErrorMessage.CHECKMARX_SERVER_CONNECTION_FAILED.getErrorMessage());
        } catch (CxTokenExpiredException ex) {
            if (retry) {
                log.warn("Access token expired for request: " + httpMethod.getURI() + ", Status code:" + statusCode + "requesting a new token. message: " + ex.getMessage());
                login();
                return request(httpMethod, contentType, entity, responseType, expectStatus, failedMsg, isCollection, false);
            }
            throw ex;
        } finally {
            httpMethod.releaseConnection();
            HttpClientUtils.closeQuietly(response);
        }
    }

    public void close() {
        HttpClientUtils.closeQuietly(apacheClient);
    }

    private void setSSLTls(String protocol, Logger log) {
        try {
            final SSLContext sslContext = SSLContext.getInstance(protocol);
            sslContext.init(null, null, null);
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            log.warn("Failed to set SSL TLS : " + e.getMessage());
        }
    }

    //TODO handle missing scope issue with management_and_orchestration_api
    private StringEntity generateSSOEntity() throws CxClientException {
        final String clientId = "cxsast_client";
        final String redirectUri = "%2Fcxwebclient%2FauthCallback.html%3F";
        final String responseType = "id_token%20token";
        final String nonce = "9313f0902ba64e50bc564f5137f35a52";
        final String isPrompt = "true";
        final String scopes = "sast_api openid sast-permissions access-control-permissions access_control_api management_and_orchestration_api".replace(" ", "%20");
        final String providerId = "2"; //windows provider id

        String redirectUrl = MessageFormat.format("/CxRestAPI/auth/identity/connect/authorize/callback" +
                        "?client_id={0}" +
                        "&redirect_uri={1}" + redirectUri +
                        "&response_type={2}" +
                        "&scope={3}" +
                        "&nonce={4}" +
                        "&prompt={5}"
                , clientId, rootUri, responseType, scopes, nonce, isPrompt);
        try {
            List<NameValuePair> urlParameters = new ArrayList<>();
            urlParameters.add(new BasicNameValuePair("redirectUrl", redirectUrl));
            urlParameters.add(new BasicNameValuePair("providerid", providerId));
            return new UrlEncodedFormEntity(urlParameters, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            throw new CxClientException(e.getMessage());
        }
    }

}
