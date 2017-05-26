/*
 * Copyright (C) 2014 Stratio (http://stratio.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.stratio.qa.utils;

import java.io.*;
import java.util.LinkedHashMap;
import java.util.Map;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GosecSSOUtils {
    private final Logger logger = LoggerFactory.getLogger(this.getClass().getCanonicalName());

    private String managementHost;

    private String managementPort = System.getProperty("MANAGEMENT_PORT", "8443");

    private String ssoHost;

    private String ssoPort = System.getProperty("SSO_PORT", "9005");

    private String userName = System.getProperty("SSO_USER", "admin");

    private String passWord = System.getProperty("SSO_PASSWORD", "1234");

    private String jsessionIdCookie;

    private String lt;

    private String execution;

    private String tgcCookie;

    private final String PROTOCOL = "https://";

    private static SSLSocketFactory sslSocketFactory = null;

    public GosecSSOUtils(String ssoHost, String managementHost, String userName, String passWord) {
        this.ssoHost = ssoHost;
        this.managementHost = managementHost;
        this.userName = userName;
        this.passWord = passWord;

    }

    public GosecSSOUtils() {
        ssoHost = System.getProperty("SSO_HOST", "gosec2.node.paas.labs");
        ssoPort = System.getProperty("SSO_PORT", "9005");
        managementHost = System.getProperty("MANAGEMENT_HOST", "gosec3.node.paas.labs");
        managementPort = System.getProperty("MANAGEMENT_PORT", "8443");
        userName = System.getProperty("SSO_USER", "admin");
        passWord = System.getProperty("passWord", "1234");
        jsessionIdCookie = "";
        lt = "";
        execution = "";
        tgcCookie = "";
    }

    /**
     * This method manage redirections flow to obtain Oauth2 Token
     * find further information in this page https://stratio.atlassian
     * .net/wiki/display/SG/SSO+-+Get+Oauth2+Token+with+Scala#SSO-GetOauth2TokenwithScala-Flow:
     * @return generated token
     * @throws Exception
     */
    public String generateGosecToken() throws Exception {
        String managementBaseUrl = getManagementBaseurl();
        logger.debug("1. Go to :" + managementBaseUrl);
        String response1_1 = sendGetRequest(managementBaseUrl, false, null, false);
        logger.debug("2. Redirect to : " + response1_1);
        String response1_2 = sendGetRequest(response1_1, true, null, false);
        logger.debug("3. Redirect to : " + response1_2 + "with" + jsessionIdCookie);
        sendGetRequest(response1_2, false, jsessionIdCookie, false);

        logger.debug("4. Go to: " + getSSOBaseurl() + " with JSESSIONID: " + jsessionIdCookie);

        String callbackLocationWhitCredential = sendPOST(getSSOBaseurl());
        logger.debug("5. Redirect to : " + callbackLocationWhitCredential + " with JSESSIONID [" + jsessionIdCookie + ",CASPRIVACY and TGC_Cookies" + getCookieWithCasPrivacy() + "]");

        String globalTokenCallback = sendGetRequest(callbackLocationWhitCredential, false, null, false);
        logger.debug("6. Redirect to : " + globalTokenCallback + " with JSESSIONID [" + jsessionIdCookie + ",CASPRIVACY and TGC_Cookies" + getCookieWithCasPrivacy() + "]");

        return tokenGenerated(sendGetRequest(globalTokenCallback, false, null, true));
    }

    /**
     * This method construct sso base url
     * @return ssoBaseUrl
     */
    public String getSSOBaseurl() {
        String ssoBaseUrl = PROTOCOL + ssoHost + ".stratio.com:" + ssoPort;
        return ssoBaseUrl + "/gosec-sso/login?service=" + ssoBaseUrl +
                    "/gosec-sso/oauth2.0/callbackAuthorize";
    }

    /**
     * This method construct management base url
     * @return management base url
     */
    public String getManagementBaseurl() {
        return PROTOCOL + managementHost + ".stratio.com:" + managementPort + "/api/scope";
    }

    /**
     * This method generate GET request using given redirections
     * @param url
     * @param isCookieNeeded
     * @param token
     * @param returnToken
     * @return callbackLocation
     * @throws Exception
     */

    public String sendGetRequest(String url, Boolean isCookieNeeded, String token, Boolean returnToken) throws
            Exception {
        String casprivacyAndTgc = "CASPRIVACY=\"\"" + ";" + tgcCookie + ";" + jsessionIdCookie;
        Boolean isCasprivacyReady = !casprivacyAndTgc.contains(";;");
        String callBackLocation;
        URL obj = new URL(url);
        HttpURLConnection response = (HttpURLConnection) obj.openConnection();
        allowUnsafeSSL((HttpsURLConnection) response);
        response.setInstanceFollowRedirects(false);

        if (token != null || isCasprivacyReady) {
            response.setRequestProperty("Cookie", isCasprivacyReady ? casprivacyAndTgc : token);
        }

        response.setRequestMethod("GET");
        int responseCode = response.getResponseCode();
        String cookieSession = response.getHeaderField("Set-Cookie");
        callBackLocation = response.getHeaderField("Location");

        logger.info("GET Response Code :: " + responseCode);
        if (isCookieNeeded) {
            jsessionIdCookie = cookieSession.substring(0, cookieSession.indexOf(";"));

        }

        if (response.getResponseCode() == HttpURLConnection.HTTP_OK) { // success
            StringBuffer responseBody = readResponseBody(response);
            lt = getHiddenInput(responseBody.toString(), "lt");
            execution = getHiddenInput(responseBody.toString(), "execution");
        }
        callBackLocation = returnToken ? cookieSession : callBackLocation;
        return callBackLocation;
    }

    public StringBuffer readResponseBody(HttpURLConnection response) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(
                response.getInputStream()));
        String inputLine;
        StringBuffer responseBody = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            responseBody.append(inputLine);
        }
        in.close();
        return responseBody;
    }

    /**
     * This method generate POST request using given redirections
     * @param url
     * @return
     * @throws Exception
     */
    public String sendPOST(String url) throws Exception {
        Map<String, String> params = getFieldParameters();

        byte[] postDataBytes = getPostDataBytes(params);
        int postDataLength = postDataBytes.length;
        URL obj = new URL(url);
        HttpURLConnection response = (HttpURLConnection) obj.openConnection();
        allowUnsafeSSL((HttpsURLConnection) response);
        response.setDoOutput(true);
        response.setInstanceFollowRedirects(false);
        response.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        response.setRequestProperty("charset", "utf-8");
        response.setRequestProperty("Content-Length", Integer.toString(postDataLength));
        response.setUseCaches(false);
        try (DataOutputStream wr = new DataOutputStream(response.getOutputStream())) {
            wr.write(postDataBytes);
        }
        response.getOutputStream().write(postDataBytes);

        String casprivacy = response.getHeaderField("Set-Cookie");
        tgcCookie = casprivacy.substring(0, casprivacy.indexOf(";"));
        logger.info("POST response Code: " + response.getResponseCode());
        if (response.getResponseCode() == HttpURLConnection.HTTP_OK) { // success
            StringBuffer responseBody = readResponseBody(response);
            // print result
            logger.info(responseBody.toString());

        }

        return response.getHeaderField("Location");
    }

    /**
     * This encode parameters string map
     * @param params
     * @return parameters in bytes
     * @throws UnsupportedEncodingException
     */
    public byte[] getPostDataBytes(Map<String, String> params) throws UnsupportedEncodingException {
        StringBuilder postData = new StringBuilder();
        for (Map.Entry<String, String> param : params.entrySet()) {
            if (postData.length() != 0) {
                postData.append('&');
            }
            postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
        }
        return postData.toString().getBytes("UTF-8");
    }

    /**
     *
     * @return
     */
    public Map<String, String> getFieldParameters() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("lt", lt);
        params.put("_eventId", "submit");
        params.put("execution", execution);
        params.put("submit", "LOGIN");
        params.put("username", userName);
        params.put("password", passWord);
        return params;
    }


    /**
     * @param responseBody
     * @param attribute
     * @return hiddenInputValue
     */
    public String getHiddenInput(String responseBody, String attribute) {
        String hiddenInputValue = "";
        String nameAux = "";
        String nameLEftMAtch = "name=\"" + attribute + "\" value=\"";
        Integer nameLimit = responseBody.indexOf(nameLEftMAtch);
        if (attribute.equals("lt")) {
            nameAux = responseBody.substring(nameLimit + nameLEftMAtch.length());
            hiddenInputValue = nameAux.substring(0, nameAux.indexOf("\" />")).trim();
        } else {
            hiddenInputValue = responseBody.substring(nameLimit + nameLEftMAtch.length()).split("\"")[0];
        }
        return hiddenInputValue;
    }

    public String getCookieWithCasPrivacy() {
        return "CASPRIVACY=\"\"" + ";" + tgcCookie + ";" + jsessionIdCookie;

    }

    public String tokenGenerated(String userToken) {
        String generatedToken = userToken.substring(userToken.indexOf("=") + 1, userToken.indexOf(";"));
        logger.info("Token generated is : [" + userToken + "]");
        return generatedToken;
    }

    /**
     * @param connection
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     */
    protected static void allowUnsafeSSL(HttpsURLConnection connection) throws NoSuchAlgorithmException,
            KeyManagementException {

        // Create the socket factory.
        // Reusing the same socket factory allows sockets to be
        // reused, supporting persistent connections.
        if (null == sslSocketFactory) {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, ALL_TRUSTING_TRUST_MANAGER, new java.security.SecureRandom());
            sslSocketFactory = sc.getSocketFactory();
        }

        connection.setSSLSocketFactory(sslSocketFactory);

        // Since we may be using a cert with a different name, we need to ignore
        // the hostname as well.
        connection.setHostnameVerifier(ALL_TRUSTING_HOSTNAME_VERIFIER);
    }

    private static final TrustManager[] ALL_TRUSTING_TRUST_MANAGER = new TrustManager[]{
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }
    };

    private static final HostnameVerifier ALL_TRUSTING_HOSTNAME_VERIFIER = new HostnameVerifier() {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };


}
