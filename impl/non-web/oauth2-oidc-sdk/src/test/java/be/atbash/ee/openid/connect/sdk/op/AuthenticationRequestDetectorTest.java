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
package be.atbash.ee.openid.connect.sdk.op;


import be.atbash.ee.oauth2.sdk.AuthorizationRequest;
import be.atbash.ee.oauth2.sdk.ResponseType;
import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.openid.connect.sdk.AuthenticationRequest;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


public class AuthenticationRequestDetectorTest {

    @Test
    public void testIsLikelyOpenID_empty() {

        assertThat(AuthenticationRequestDetector.isLikelyOpenID(Collections.<String, List<String>>emptyMap())).isFalse();
    }

    @Test
    public void testIsLikelyOpenID_plainMinimalOAuth() {

        assertThat(AuthenticationRequestDetector.isLikelyOpenID(
                new AuthorizationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        new ClientID("123"))
                        .build()
                        .toParameters()
        )).isFalse();

    }

    @Test
    public void testIsLikelyOpenID_minimalOpenID() {

        assertThat(AuthenticationRequestDetector.isLikelyOpenID(
                new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        new Scope("openid"),
                        new ClientID("123"),
                        URI.create("https://example.com/cb"))
                        .build()
                        .toParameters()
        )).isTrue();
    }
}
