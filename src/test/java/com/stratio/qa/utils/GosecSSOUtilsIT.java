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

import org.testng.annotations.*;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.mockito.Mockito.*;

import static org.assertj.core.api.Assertions.assertThat;


public class GosecSSOUtilsIT {
    private final Logger logger = LoggerFactory
            .getLogger(GosecSSOUtilsIT.class);
    private static GosecSSOUtils gosecUtils = new GosecSSOUtils();
    private static GosecSSOUtils mockedGosecSSOUtils;
    private String url = "https://gosec2.node.paas.labs.stratio" +
            ".com:9005/gosec-sso/oauth2.0/callbackAuthorize?ticket=ST-92-bi0RIgCbJzI4L7W9BItw-gosec2.node.paas.labs.stratio.com";
    private String responseBody = "2Foauth2.0%2FcallbackAuthorize\" method=\"post\">            <div class=\"login__errors\">    " +
            "                                  <input type=\"hidden\" name=\"lt\" value=\"LT-66-k4xWul35hkbZjMdA9BcXUmlMlQb02w-gosec2.node.paas.labs.stratio.com\" />                     <input type=\"hidden\" name=\"execution\" value=\"4c21bae8-8eaa-40e7-b9f8-c7e457d028db_AAAAIgAAABCiR+F4x2lS9YCbc8YK2/aFAAAABmFlczEyOJwKG";
    private String callbackLocator1 = "https://gosec2.node.paas.labs.stratio" +
            ".com:9005/gosec-sso/oauth2.0/callbackAuthorize?ticket=ST-92-bi0RIgCbJzI4L7W9BItw-gosec2.node.paas.labs.stratio.com";
    private String callbackLocator2 = "https://gosec2.node.paas.labs" +
            ".stratio.com:9005/gosec-sso/oauth2.0/authorize?redirect_uri=https://gosec3.node.paas.labs.stratio.com:8443/login&client_id=gosec-management-oauth-id";
    private String callbackLocator3 = "https://gosec2.node.paas.labs.stratio.com:9005/gosec-sso/login?service=https%3A%2F%2Fgosec2.node.paas.labs.stratio.com%3A9005%2Fgosec-sso%2Foauth2.0%2FcallbackAuthorize";
    private String jSessionId = "JSESSIONID=1bc2n7j3i6b9zr6f091mz388h";
    private String returnedJSessionId = "JSESSIONID=1nit9vprgqd5h4pay7u86fuw9;Path=/gosec-sso;Secure";
    private String userToken = "0e65edb6-d331-4fcf-8880-fadef0234c1d";

    @BeforeMethod
    public void GosecSSOUtilsSetUp() throws Exception {

        mockedGosecSSOUtils = Mockito.mock(GosecSSOUtils.class);
        when(mockedGosecSSOUtils.sendGetRequest(url, false, null, false)).thenReturn(callbackLocator2);
        when(mockedGosecSSOUtils.sendGetRequest(url, true, null, false)).thenReturn(callbackLocator3);
        when(mockedGosecSSOUtils.sendGetRequest(url, false, jSessionId, false)).thenReturn(callbackLocator3);
        when(mockedGosecSSOUtils.sendGetRequest(url, false, jSessionId, true)).thenReturn(returnedJSessionId);
        when(mockedGosecSSOUtils.sendPOST(url)).thenReturn(callbackLocator1);
        when(mockedGosecSSOUtils.generateGosecToken()).thenReturn(userToken);
    }

    @Test
    public void gosecUtilsSendGetRequestTest() throws Exception {
        assertThat(mockedGosecSSOUtils.sendGetRequest(url, false, null, false).contains(callbackLocator2)).isTrue();
        assertThat(mockedGosecSSOUtils.sendGetRequest(url, true, null, false).contains(callbackLocator3)).isTrue();
        assertThat(mockedGosecSSOUtils.sendGetRequest(url, false, jSessionId, false).contains(callbackLocator3)).isTrue();
        assertThat(mockedGosecSSOUtils.sendGetRequest(url, false, jSessionId, true).contains(returnedJSessionId)).isTrue();
    }

    @Test
    public void gosecUtilsSendPostRequestTest() throws Exception {
        assertThat(mockedGosecSSOUtils.sendPOST(url).equals(callbackLocator1)).isTrue();
    }

    @Test
    public void gosecUtilsGenerateGosecTokenTest() throws Exception {
        assertThat(mockedGosecSSOUtils.generateGosecToken().equals(userToken)).isTrue();
    }


    @Test
    public void gosecUtilsGetHiddenInputTest() throws Exception {
        assertThat(gosecUtils.getHiddenInput(responseBody, "lt").equals
                ("LT-66-k4xWul35hkbZjMdA9BcXUmlMlQb02w-gosec2.node.paas.labs.stratio.com")).isTrue();
        assertThat(gosecUtils.getHiddenInput(responseBody, "execution").equals("4c21bae8-8eaa-40e7-b9f8-c7e457d028db_AAAAIgAAABCiR+F4x2lS9YCbc8YK2/aFAAAABmFlczEyOJwKG")).isTrue();

    }

    @Test
    public void gosecUtilsTokenGeneratedTest() throws Exception {
        String tokens = gosecUtils.tokenGenerated("user=0e65edb6-d331-4fcf-8880-fadef0234c1d; Max-Age=7200; Path=/");
        assertThat(tokens.equals(userToken));
    }

    @Test
    public void gosecUtilsGetCookiesWithCasprivacyTest() throws Exception {
        assertThat(gosecUtils.getCookieWithCasPrivacy().contains("CASPRIVACY=\"\";;")).isTrue();
    }
}
