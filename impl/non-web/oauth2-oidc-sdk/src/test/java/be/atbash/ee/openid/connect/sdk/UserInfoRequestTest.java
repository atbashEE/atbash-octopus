/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the UserInfo request.
 */
public class UserInfoRequestTest {

    @Test
    public void testMinimalConstructor()
            throws Exception {

        URI endpointURI = new URI("https://c2id.com/userinfo");
        BearerAccessToken token = new BearerAccessToken();

        UserInfoRequest request = new UserInfoRequest(endpointURI, token);

        assertThat(request.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(request.getAccessToken()).isEqualTo(token);
        assertThat(request.getMethod()).isEqualTo(HTTPRequest.Method.GET);

        HTTPRequest httpRequest = request.toHTTPRequest();

        assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.GET);
        assertThat(httpRequest.getURL().toURI()).isEqualTo(endpointURI);
        assertThat(httpRequest.getQuery()).isNull();
        assertThat(httpRequest.getAuthorization()).isEqualTo(token.toAuthorizationHeader());

        request = UserInfoRequest.parse(httpRequest);

        assertThat(request.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(request.getAccessToken()).isEqualTo(token);
        assertThat(request.getMethod()).isEqualTo(HTTPRequest.Method.GET);
    }

    @Test
    public void testFullConstructor()
            throws Exception {

        URI url = new URI("https://c2id.com/userinfo");
        BearerAccessToken token = new BearerAccessToken();

        UserInfoRequest request = new UserInfoRequest(url, HTTPRequest.Method.POST, token);

        assertThat(request.getEndpointURI()).isEqualTo(url);
        assertThat(request.getAccessToken()).isEqualTo(token);
        assertThat(request.getMethod()).isEqualTo(HTTPRequest.Method.POST);

        HTTPRequest httpRequest = request.toHTTPRequest();

        assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
        assertThat(httpRequest.getURL().toURI()).isEqualTo(url);
        assertThat(httpRequest.getContentType().toString()).isEqualTo("application/x-www-form-urlencoded; charset=UTF-8");
        assertThat(httpRequest.getQuery()).isEqualTo("access_token=" + token.getValue());
        assertThat(httpRequest.getAuthorization()).isNull();

        request = UserInfoRequest.parse(httpRequest);

        assertThat(request.getEndpointURI()).isEqualTo(url);
        assertThat(request.getAccessToken()).isEqualTo(token);
        assertThat(request.getMethod()).isEqualTo(HTTPRequest.Method.POST);
    }
}
