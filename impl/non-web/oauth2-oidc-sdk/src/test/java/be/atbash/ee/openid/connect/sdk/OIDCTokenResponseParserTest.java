/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
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


import be.atbash.ee.oauth2.sdk.OAuth2Error;
import be.atbash.ee.oauth2.sdk.TokenErrorResponse;
import be.atbash.ee.oauth2.sdk.TokenResponse;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.oauth2.sdk.token.RefreshToken;
import be.atbash.ee.openid.connect.sdk.token.OIDCTokens;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the OpenID Connect token response parser.
 */
public class OIDCTokenResponseParserTest {


    // Example ID token from OIDC Standard
    private static final String ID_TOKEN_STRING =
            "eyJhbGciOiJSUzI1NiJ9.ew0KICAgICJpc3MiOiAiaHR0cDovL" +
                    "3NlcnZlci5leGFtcGxlLmNvbSIsDQogICAgInVzZXJfaWQiOiAiMjQ4Mjg5NzYxM" +
                    "DAxIiwNCiAgICAiYXVkIjogInM2QmhkUmtxdDMiLA0KICAgICJub25jZSI6ICJuL" +
                    "TBTNl9XekEyTWoiLA0KICAgICJleHAiOiAxMzExMjgxOTcwLA0KICAgICJpYXQiO" +
                    "iAxMzExMjgwOTcwDQp9.lsQI_KNHpl58YY24G9tUHXr3Yp7OKYnEaVpRL0KI4szT" +
                    "D6GXpZcgxIpkOCcajyDiIv62R9rBWASV191Akk1BM36gUMm8H5s8xyxNdRfBViCa" +
                    "xTqHA7X_vV3U-tSWl6McR5qaSJaNQBpg1oGPjZdPG7zWCG-yEJC4-Fbx2FPOS7-h" +
                    "5V0k33O5Okd-OoDUKoFPMd6ur5cIwsNyBazcsHdFHqWlCby5nl_HZdW-PHq0gjzy" +
                    "JydB5eYIvOfOHYBRVML9fKwdOLM2xVxJsPwvy3BqlVKc593p2WwItIg52ILWrc6A" +
                    "tqkqHxKsAXLVyAoVInYkl_NDBkCqYe2KgNJFzfEC8g";


    public static JWT ID_TOKEN;


    static {
        try {
            ID_TOKEN = JWTParser.parse(ID_TOKEN_STRING);
        } catch (Exception e) {
            ID_TOKEN = null;
        }
    }

    @Test
    public void testParseSuccess()
            throws Exception {

        OIDCTokens tokens = new OIDCTokens(
                ID_TOKEN,
                new BearerAccessToken("abc123"),
                new RefreshToken("def456"));

        OIDCTokenResponse response = new OIDCTokenResponse(tokens);

        assertThat(response.getOIDCTokens()).isEqualTo(tokens);
        assertThat(response.getTokens()).isEqualTo(tokens);

        HTTPResponse httpResponse = response.toHTTPResponse();

        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

        assertThat(tokenResponse.indicatesSuccess()).isTrue();

        response = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

        assertThat(response.getTokens().getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(response.getTokens().getRefreshToken().getValue()).isEqualTo("def456");
        assertThat(response.getOIDCTokens().getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getOIDCTokens().getIDToken().serialize()).isEqualTo(ID_TOKEN_STRING);
    }


    // Token response with no id_token (e.g. in response to a refresh_token grant)
    @Test
    public void testParseSuccess_noIDToken()
            throws Exception {

        OIDCTokens tokens = new OIDCTokens(
                new BearerAccessToken("abc123"),
                new RefreshToken("def456"));

        OIDCTokenResponse response = new OIDCTokenResponse(tokens);

        assertThat(response.getOIDCTokens()).isEqualTo(tokens);
        assertThat(response.getTokens()).isEqualTo(tokens);

        HTTPResponse httpResponse = response.toHTTPResponse();

        System.out.println(httpResponse.getContent());

        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

        assertThat(tokenResponse.indicatesSuccess()).isTrue();

        response = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

        assertThat(response.getTokens().getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(response.getTokens().getRefreshToken().getValue()).isEqualTo("def456");
        assertThat(response.getOIDCTokens().getIDToken()).isNull();
        assertThat(response.getOIDCTokens().getIDTokenString()).isNull();
    }

    @Test
    public void testParseError()
            throws Exception {

        TokenErrorResponse response = new TokenErrorResponse(OAuth2Error.INVALID_GRANT);

        HTTPResponse httpResponse = response.toHTTPResponse();

        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

        assertThat(tokenResponse.indicatesSuccess()).isFalse();
        response = tokenResponse.toErrorResponse();
        assertThat(response.getErrorObject()).isEqualTo(OAuth2Error.INVALID_GRANT);
    }
}
