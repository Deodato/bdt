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

import java.util.LinkedHashMap;
import java.util.Map;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
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

    private String userName = System.getProperty("userName", "admin");

    private String passWord = System.getProperty("passWord", "1234");

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
        userName = System.getProperty("userName", "admin");
        passWord = System.getProperty("passWord", "1234");
        jsessionIdCookie = "";
        lt = "";
        execution = "";
        tgcCookie = "";
    }

    public String generateGosecToken() throws Exception {
        String managementBaseUrl = PROTOCOL + managementHost + ".stratio.com:" + managementPort + "/api/scope";
        String ssoBase = PROTOCOL + ssoHost + ".stratio.com:" + ssoPort;
        String ssoBaseURL = ssoBase + "/gosec-sso/login?service=" + ssoBase + "/gosec-sso/oauth2.0/callbackAuthorize";
        logger.debug("1. Go to :" + managementBaseUrl);
        String response1_1 = sendGetRequest(managementBaseUrl, false, null, false);
        logger.debug("2. Redirect to : " + response1_1);
        String response1_2 = sendGetRequest(response1_1, true, null, false);
        logger.debug("3. Redirect to : " + response1_2 + "with" + jsessionIdCookie);
        sendGetRequest(response1_2, false, jsessionIdCookie, false);

        logger.debug("4. Go to: " + ssoBaseURL + "with JSESSIONID: " + jsessionIdCookie);

        String location22 = sendPOST(ssoBaseURL);
        logger.debug("5. Redirect to : " + location22 + "with JSESSIONID [" + jsessionIdCookie + ",CASPRIVACY and TGC_Cookies" + getCookieWithCasPrivacy() + "]");

        String location23 = sendGetRequest(location22, false, null, false);
        logger.debug("6. Redirect to : " + location23 + "with JSESSIONID [" + jsessionIdCookie + ",CASPRIVACY and TGC_Cookies" + getCookieWithCasPrivacy() + "]");

        String tokenCookie = sendGetRequest(location23, false, null, true);
        return tokenGenerated(tokenCookie);
    }


    public String sendGetRequest(String url, Boolean isCookieNeeded, String token, Boolean returnToken) throws
            Exception {
        String callBackLocation = "";
        String casprivacyAndTgc = getCookieWithCasPrivacy();
        Boolean isCasprivacyReady = !casprivacyAndTgc.contains(";;");

        URL obj = new URL(url);
        HttpURLConnection response
                = (HttpURLConnection) obj.openConnection();
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
            BufferedReader in = new BufferedReader(new InputStreamReader(
                    response.getInputStream()));
            String inputLine;
            StringBuffer responseBody = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                responseBody.append(inputLine);
            }
            in.close();
            lt = getHiddenInput(responseBody.toString(), "lt");
            execution = getHiddenInput(responseBody.toString(), "execution");
        }
        callBackLocation = returnToken ? cookieSession : callBackLocation;
        return callBackLocation;
    }

    public String sendPOST(String url) throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("lt", lt);
        params.put("_eventId", "submit");
        params.put("execution", execution);
        params.put("submit", "LOGIN");
        params.put("username", userName);
        params.put("password", passWord);


        StringBuilder postData = new StringBuilder();
        for (Map.Entry<String, String> param : params.entrySet()) {
            if (postData.length() != 0) {
                postData.append('&');
            }
            postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
        }
        byte[] postDataBytes = postData.toString().getBytes("UTF-8");
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

        int responseCode4 = response.getResponseCode();

        String casprivacy = response.getHeaderField("Set-Cookie");
        tgcCookie = casprivacy.substring(0, casprivacy.indexOf(";"));
        String location = response.getHeaderField("Location");
        logger.info("POST response Code: " + responseCode4);
        if (responseCode4 == HttpURLConnection.HTTP_OK) { // success
            BufferedReader in = new BufferedReader(new InputStreamReader(
                    response.getInputStream()));
            String inputLine;
            StringBuffer responseBody = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                responseBody.append(inputLine);
            }
            in.close();
            // print result
            logger.info(responseBody.toString());

        }

        return location;
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
