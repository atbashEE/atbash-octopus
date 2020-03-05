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
package be.atbash.ee.oauth2.sdk.auth;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests client secret basic authentication.
 */
public class ClientSecretBasicTest {

    @Test
    public void testSerializeAndParse()
            throws OAuth2JSONParseException {

        // Test vectors from OAuth 2.0 RFC

        String id = "s6BhdRkqt3";
        String pw = "7Fjfp0ZBr1KtDRbnfVdmIw";

        ClientID clientID = new ClientID(id);
        Secret secret = new Secret(pw);

        ClientSecretBasic csb = new ClientSecretBasic(clientID, secret);

        assertThat(csb).isInstanceOf(PlainClientSecret.class);

        assertThat(csb.getMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        assertThat(csb.getClientID().toString()).isEqualTo(id);
        assertThat(csb.getClientSecret().getValue()).isEqualTo(pw);

        String header = csb.toHTTPAuthorizationHeader();

        assertThat(header).isEqualTo("Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3");

        csb = ClientSecretBasic.parse(header);

        assertThat(csb.getClientID().toString()).isEqualTo(id);
        assertThat(csb.getClientSecret().getValue()).isEqualTo(pw);
    }

    @Test
    public void testParseAndSerialize()
            throws Exception {

        String header = "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3";

        ClientSecretBasic csb = ClientSecretBasic.parse(header);

        assertThat(csb.getClientID().getValue()).isEqualTo("s6BhdRkqt3");
        assertThat(csb.getClientSecret().getValue()).isEqualTo("7Fjfp0ZBr1KtDRbnfVdmIw");
    }

    @Test
    public void testSecretWithBackslashes()
            throws Exception {

        String id = "IX-1FXURP1U93W11";
        String pw = "cXqXbCJTOUJfypCD92ZNNviQxvYitAN6vH0zF8h/nFy6+yH7ERVlPpIZnUqYfCzaHZYkziI7QBCK88juLTC/t9WwjiMi6WbecE3y+tnD2lniI6PK7n4jMTBhaJPNqfHpvdh13GZswc92HtPSLQYbiKxzgAPhnmFa/1hV+GfmnEp+IXnDRukHA8AaX6L3d4x6T608+2dZRnqOM4+DB7K4vFNm+3bYcEpHz5zhBAulXQMp+GziCoKRcWrQfjHx1cSsmh+R/F6BZLHkVvNF6XKaKA2sDlxc9Bx3EwfNFJYojWiGr+WTD8slrDw6yfbZKTYsfgYFCYf0gSUsV8mHIxaZQA==";

        ClientID clientID = new ClientID(id);
        Secret secret = new Secret(pw);

        ClientSecretBasic csb = new ClientSecretBasic(clientID, secret);

        String header = csb.toHTTPAuthorizationHeader();
        csb = ClientSecretBasic.parse(header);

        assertThat(clientID.equals(csb.getClientID())).isTrue();
        assertThat(secret.equals(csb.getClientSecret())).isTrue();

        assertThat(csb.getClientID().getValue()).isEqualTo(id);
        assertThat(csb.getClientSecret().getValue()).isEqualTo(pw);
    }

    @Test
    public void testNonEscapedSecretWithLegacyBasicAuth()
            throws Exception {

        // Test legacy HTTP basic auth without HTTP URL escape of charc in username + password
        // See http://tools.ietf.org/html/rfc6749#section-2.3.1

        String id = "IX-1FXURP1U93W11";
        String pw = "cXqXbCJTOUJfypCD92ZNNviQxvYitAN6vH0zF8h\\/nFy6+yH7ERVlPpIZnUqYfCzaHZYkziI7QBCK88juLTC\\/t9WwjiMi6WbecE3y+tnD2lniI6PK7n4jMTBhaJPNqfHpvdh13GZswc92HtPSLQYbiKxzgAPhnmFa\\/1hV+GfmnEp+IXnDRukHA8AaX6L3d4x6T608+2dZRnqOM4+DB7K4vFNm+3bYcEpHz5zhBAulXQMp+GziCoKRcWrQfjHx1cSsmh+R\\/F6BZLHkVvNF6XKaKA2sDlxc9Bx3EwfNFJYojWiGr+WTD8slrDw6yfbZKTYsfgYFCYf0gSUsV8mHIxaZQA==";

        String credentials = id + ":" + pw;

        String header = "Basic " + Base64Value.encode(credentials.getBytes(StandardCharsets.UTF_8));

        assertThat("Basic SVgtMUZYVVJQMVU5M1cxMTpjWHFYYkNKVE9VSmZ5cENEOTJaTk52aVF4dllpdEFONnZIMHpGOGhcL25GeTYreUg3RVJWbFBwSVpuVXFZZkN6YUhaWWt6aUk3UUJDSzg4anVMVENcL3Q5V3dqaU1pNldiZWNFM3krdG5EMmxuaUk2UEs3bjRqTVRCaGFKUE5xZkhwdmRoMTNHWnN3YzkySHRQU0xRWWJpS3h6Z0FQaG5tRmFcLzFoVitHZm1uRXArSVhuRFJ1a0hBOEFhWDZMM2Q0eDZUNjA4KzJkWlJucU9NNCtEQjdLNHZGTm0rM2JZY0VwSHo1emhCQXVsWFFNcCtHemlDb0tSY1dyUWZqSHgxY1NzbWgrUlwvRjZCWkxIa1Z2TkY2WEthS0Eyc0RseGM5QngzRXdmTkZKWW9qV2lHcitXVEQ4c2xyRHc2eWZiWktUWXNmZ1lGQ1lmMGdTVXNWOG1ISXhhWlFBPT0=").isEqualTo(header);
    }

    @Test
    public void testWithLegacyExample() {

        String id = "Aladdin";
        String pw = "open sesame";

        ClientSecretBasic cb = new ClientSecretBasic(new ClientID(id), new Secret(pw));

        // Must not match legacy example
        assertThat(cb.toHTTPAuthorizationHeader()).isNotEqualTo("QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }

    @Test
    public void testParse_missingCredentialsDelimiter() {

        String id = "alice";
        String pw = "secret";
        String concat = id + "" + pw; // ':' delimiter
        String b64 = Base64Value.encode(concat).toString();

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> ClientSecretBasic.parse("Basic " + b64));

        assertThat(exception.getMessage()).isEqualTo("Malformed client secret basic authentication (see RFC 6749, section 2.3.1): Missing credentials delimiter \":\"");

    }

    @Test
    public void testParse_tooManyAuthzHeaderTokens() {


        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> ClientSecretBasic.parse("Basic abc def"));

        assertThat(exception.getMessage()).isEqualTo("Malformed client secret basic authentication (see RFC 6749, section 2.3.1): Unexpected number of HTTP Authorization header value parts: 3");

    }


    // iss 208
    @Test
    public void testIllegalHexCharsInAuthzHeader() {


        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> ClientSecretBasic.parse("Basic KVQdqB25zeFg4duoJf7ZYo4wDMXtQjqlpxWdgFm06vc"));

        assertThat(exception.getMessage()).isEqualTo("Malformed client secret basic authentication (see RFC 6749, section 2.3.1): Invalid URL encoding");

    }
}
