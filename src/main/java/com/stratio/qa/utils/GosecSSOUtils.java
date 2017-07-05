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
import java.net.URI;
import java.security.SecureRandom;
import java.util.*;
import java.security.cert.X509Certificate;
import java.util.stream.Collectors;
import javax.net.ssl.*;

import org.apache.http.*;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.message.BasicNameValuePair;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GosecSSOUtils {
    private final Logger logger = LoggerFactory.getLogger(this.getClass().getCanonicalName());

    public String userName = System.getProperty("user", "admin");

    public String passWord = System.getProperty("passWord", "1234");

    public String ssoHost = System.getProperty("ssoHost", "sso.paas.labs.stratio.com");

    public String managementHost = System.getProperty("managementHost", "/service/gosecmanagement");

    public GosecSSOUtils(String ssHost, String userName, String passWord) {
        this.ssoHost = ssHost;
        this.userName = userName;
        this.passWord = passWord;
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

    /**
     * This method provide dcos and sso token to be used to generate client cookie
     * @return cookieToken
     * @throws Exception
     */
    public HashMap<String, String> ssoTokenGenerator() throws
            Exception {
        String protocol = "https://";
        SSLContext sslContext = SSLContext.getInstance("SSL");
        // set up a TrustManager that trusts everything
        sslContext.init(null, ALL_TRUSTING_TRUST_MANAGER, new SecureRandom());
        HttpClientContext context = HttpClientContext.create();
        HttpGet httpGet = new HttpGet(protocol + this.ssoHost + "/login");
        HttpClient client = HttpClientBuilder.create()
                .setSslcontext(sslContext)
                .setRedirectStrategy(new LaxRedirectStrategy())
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setCookieSpec(CookieSpecs.BEST_MATCH)
                        .setCircularRedirectsAllowed(true).build()).build();
        org.apache.http.HttpResponse response = client.execute(httpGet, context);
        logger.debug(response.getStatusLine().toString());
        Document doc = Jsoup.parse(getStringFromIS(response.getEntity().getContent()));
        Elements code = doc.select("[name=lt]");
        String loginCode = code.attr("value");
        String executionCode = doc.select("[name=execution]").attr("value");
        for (Header oneHeader : response.getAllHeaders()) {
            logger.debug(oneHeader.getName() + ":" + oneHeader.getValue());
        }

        URI redirect = context.getRedirectLocations().get(context.getRedirectLocations().size() - 1);

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("_eventId", "submit"));
        params.add(new BasicNameValuePair("submit", "LOGIN"));
        params.add(new BasicNameValuePair("username", this.userName));
        params.add(new BasicNameValuePair("password", passWord));
        params.add(new BasicNameValuePair("lt", loginCode));
        params.add(new BasicNameValuePair("execution", executionCode));
        HttpPost httpPost = new HttpPost(redirect);
        httpPost.setEntity(new UrlEncodedFormEntity(params));
        org.apache.http.HttpResponse secondResponse = client.execute(httpPost, context);

        for (Header oneHeader : secondResponse.getAllHeaders()) {
            logger.debug(oneHeader.getName() + ":" + oneHeader.getValue());
        }

        HttpGet managementGet = new HttpGet(protocol + ssoHost + managementHost);
        client.execute(managementGet, context);

        HashMap<String, String> cookieToken = new HashMap<>();
        for (Cookie oneCookie : context.getCookieStore().getCookies()) {
            logger.info(oneCookie.getName() + ":" + oneCookie.getValue());
            cookieToken.put(oneCookie.getName(), oneCookie.getValue());
        }
        return cookieToken;
    }

    private String getStringFromIS(InputStream stream) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
            return reader.lines().collect(Collectors.joining("\n"));
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

    }
}
