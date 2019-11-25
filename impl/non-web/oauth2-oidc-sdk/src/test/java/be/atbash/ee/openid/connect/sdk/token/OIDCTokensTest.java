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
package be.atbash.ee.openid.connect.sdk.token;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.token.*;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

/**
 * Tests the OpenID Connect tokens class.
 */
public class OIDCTokensTest {


    // Example ID token from OIDC Standard
    private static final String ID_TOKEN_STRING = "eyJhbGciOiJSUzI1NiJ9.ew0KICAgICJpc3MiOiAiaHR0cDovL" +
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
    public void testAllDefined()
            throws OAuth2JSONParseException {

        AccessToken accessToken = new BearerAccessToken(60L, Scope.parse("openid email"));
        RefreshToken refreshToken = new RefreshToken();

        OIDCTokens tokens = new OIDCTokens(ID_TOKEN, accessToken, refreshToken);

        assertThat(tokens.getIDToken()).isEqualTo(ID_TOKEN);
        assertThat(tokens.getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(tokens.getAccessToken()).isEqualTo(accessToken);
        assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
        assertThat(tokens.getRefreshToken()).isEqualTo(refreshToken);

        assertThat(tokens.getParameterNames().contains("id_token")).isTrue();
        assertThat(tokens.getParameterNames().contains("token_type")).isTrue();
        assertThat(tokens.getParameterNames().contains("access_token")).isTrue();
        assertThat(tokens.getParameterNames().contains("expires_in")).isTrue();
        assertThat(tokens.getParameterNames().contains("scope")).isTrue();
        assertThat(tokens.getParameterNames().contains("refresh_token")).isTrue();
        assertThat(tokens.getParameterNames()).hasSize(6);

        JsonObject jsonObject = tokens.toJSONObject().build();
        assertThat(jsonObject.getString("id_token")).isEqualTo(ID_TOKEN_STRING);
        assertThat(jsonObject.getString("token_type")).isEqualTo("Bearer");
        assertThat(jsonObject.getString("access_token")).isEqualTo(accessToken.getValue());
        assertThat(jsonObject.getJsonNumber("expires_in").longValue()).isEqualTo(60L);
        assertThat(jsonObject.getString("scope")).isEqualTo("openid email");
        assertThat(jsonObject.getString("refresh_token")).isEqualTo(refreshToken.getValue());
        assertThat(jsonObject).hasSize(6);

        tokens = OIDCTokens.parse(jsonObject);

        assertThat(tokens.getIDToken().getParsedString()).isEqualTo(ID_TOKEN.getParsedString());
        assertThat(tokens.getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(tokens.getAccessToken().getValue()).isEqualTo(accessToken.getValue());
        assertThat(tokens.getAccessToken().getLifetime()).isEqualTo(accessToken.getLifetime());
        assertThat(tokens.getAccessToken().getScope()).isEqualTo(accessToken.getScope());
        assertThat(tokens.getRefreshToken().getValue()).isEqualTo(refreshToken.getValue());
    }

    @Test
    public void testAllDefined_fromIDTokenString()
            throws OAuth2JSONParseException {

        AccessToken accessToken = new BearerAccessToken(60L, Scope.parse("openid email"));
        RefreshToken refreshToken = new RefreshToken();

        OIDCTokens tokens = new OIDCTokens(ID_TOKEN_STRING, accessToken, refreshToken);

        assertThat(tokens.getIDToken().getParsedString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(tokens.getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(tokens.getAccessToken()).isEqualTo(accessToken);
        assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
        assertThat(tokens.getRefreshToken()).isEqualTo(refreshToken);

        assertThat(tokens.getParameterNames().contains("id_token")).isTrue();
        assertThat(tokens.getParameterNames().contains("token_type")).isTrue();
        assertThat(tokens.getParameterNames().contains("access_token")).isTrue();
        assertThat(tokens.getParameterNames().contains("expires_in")).isTrue();
        assertThat(tokens.getParameterNames().contains("scope")).isTrue();
        assertThat(tokens.getParameterNames().contains("refresh_token")).isTrue();
        assertThat(tokens.getParameterNames()).hasSize(6);

        JsonObject jsonObject = tokens.toJSONObject().build();
        assertThat(jsonObject.getString("id_token")).isEqualTo(ID_TOKEN_STRING);
        assertThat(jsonObject.getString("token_type")).isEqualTo("Bearer");
        assertThat(jsonObject.getString("access_token")).isEqualTo(accessToken.getValue());
        assertThat(jsonObject.getJsonNumber("expires_in").longValue()).isEqualTo(60L);
        assertThat(jsonObject.getString("scope")).isEqualTo("openid email");
        assertThat(jsonObject.getString("refresh_token")).isEqualTo(refreshToken.getValue());
        assertThat(jsonObject).hasSize(6);

        tokens = OIDCTokens.parse(jsonObject);

        assertThat(tokens.getIDToken().getParsedString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(tokens.getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(tokens.getAccessToken().getValue()).isEqualTo(accessToken.getValue());
        assertThat(tokens.getAccessToken().getLifetime()).isEqualTo(accessToken.getLifetime());
        assertThat(tokens.getAccessToken().getScope()).isEqualTo(accessToken.getScope());
        assertThat(tokens.getRefreshToken().getValue()).isEqualTo(refreshToken.getValue());
    }


    // The token response from a refresh token grant may not include an id_token
    @Test
    public void testNoIDToken()
            throws OAuth2JSONParseException {

        AccessToken accessToken = new BearerAccessToken();

        OIDCTokens tokens = new OIDCTokens(accessToken, null);

        assertThat(tokens.getIDToken()).isNull();
        assertThat(tokens.getIDTokenString()).isNull();
        assertThat(tokens.getAccessToken()).isEqualTo(accessToken);
        assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
        assertThat(tokens.getRefreshToken()).isNull();

        assertThat(tokens.getParameterNames().contains("token_type")).isTrue();
        assertThat(tokens.getParameterNames().contains("access_token")).isTrue();
        assertThat(tokens.getParameterNames()).hasSize(2);

        JsonObject jsonObject = tokens.toJSONObject().build();
        assertThat(jsonObject.getString("token_type")).isEqualTo("Bearer");
        assertThat(jsonObject.getString("access_token")).isEqualTo(accessToken.getValue());
        assertThat(jsonObject).hasSize(2);

        tokens = OIDCTokens.parse(jsonObject);

        assertThat(tokens.getIDToken()).isNull();
        assertThat(tokens.getIDTokenString()).isNull();
        assertThat(tokens.getAccessToken().getValue()).isEqualTo(accessToken.getValue());
        assertThat(tokens.getAccessToken().getLifetime()).isEqualTo(0L);
        assertThat(tokens.getAccessToken().getScope()).isNull();
        assertThat(tokens.getRefreshToken()).isNull();
    }

    @Test
    public void testMinimal()
            throws OAuth2JSONParseException {

        AccessToken accessToken = new BearerAccessToken();

        OIDCTokens tokens = new OIDCTokens(ID_TOKEN, accessToken, null);

        assertThat(tokens.getIDToken()).isEqualTo(ID_TOKEN);
        assertThat(tokens.getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(tokens.getAccessToken()).isEqualTo(accessToken);
        assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
        assertThat(tokens.getRefreshToken()).isNull();

        assertThat(tokens.getParameterNames().contains("id_token")).isTrue();
        assertThat(tokens.getParameterNames().contains("token_type")).isTrue();
        assertThat(tokens.getParameterNames().contains("access_token")).isTrue();
        assertThat(tokens.getParameterNames()).hasSize(3);

        JsonObject jsonObject = tokens.toJSONObject().build();
        assertThat(jsonObject.getString("id_token")).isEqualTo(ID_TOKEN_STRING);
        assertThat(jsonObject.getString("token_type")).isEqualTo("Bearer");
        assertThat(jsonObject.getString("access_token")).isEqualTo(accessToken.getValue());
        assertThat(jsonObject).hasSize(3);

        tokens = OIDCTokens.parse(jsonObject);

        assertThat(tokens.getIDToken().getParsedString()).isEqualTo(ID_TOKEN.getParsedString());
        assertThat(tokens.getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(tokens.getAccessToken().getValue()).isEqualTo(accessToken.getValue());
        assertThat(tokens.getAccessToken().getLifetime()).isEqualTo(0L);
        assertThat(tokens.getAccessToken().getScope()).isNull();
        assertThat(tokens.getRefreshToken()).isNull();
    }

    @Test
    public void testMinimal_fromIDTokenString()
            throws OAuth2JSONParseException {

        AccessToken accessToken = new BearerAccessToken();

        OIDCTokens tokens = new OIDCTokens(ID_TOKEN_STRING, accessToken, null);

        assertThat(tokens.getIDToken().getParsedString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(tokens.getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(tokens.getAccessToken()).isEqualTo(accessToken);
        assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
        assertThat(tokens.getRefreshToken()).isNull();

        assertThat(tokens.getParameterNames().contains("id_token")).isTrue();
        assertThat(tokens.getParameterNames().contains("token_type")).isTrue();
        assertThat(tokens.getParameterNames().contains("access_token")).isTrue();
        assertThat(tokens.getParameterNames()).hasSize(3);

        JsonObject jsonObject = tokens.toJSONObject().build();
        assertThat(jsonObject.getString("id_token")).isEqualTo(ID_TOKEN_STRING);
        assertThat(jsonObject.getString("token_type")).isEqualTo("Bearer");
        assertThat(jsonObject.getString("access_token")).isEqualTo(accessToken.getValue());
        assertThat(jsonObject).hasSize(3);

        tokens = OIDCTokens.parse(jsonObject);

        assertThat(tokens.getIDToken().getParsedString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(tokens.getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(tokens.getAccessToken().getValue()).isEqualTo(accessToken.getValue());
        assertThat(tokens.getAccessToken().getLifetime()).isEqualTo(0L);
        assertThat(tokens.getAccessToken().getScope()).isNull();
        assertThat(tokens.getRefreshToken()).isNull();
    }

    @Test
    public void testMissingIDToken() {

        try {
            new OIDCTokens((JWT) null, new BearerAccessToken(), null);
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The ID token must not be null");
        }
    }

    @Test
    public void testMissingIDTokenString() {

        try {
            new OIDCTokens((String) null, new BearerAccessToken(), null);
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The ID token string must not be null");
        }
    }

    @Test
    public void testParseInvalidIDToken() {

        JsonObjectBuilder jsonObjectbuilder = Json.createObjectBuilder();
        jsonObjectbuilder.add("id_token", "ey..."); // invalid
        jsonObjectbuilder.add("token_type", "Bearer");
        jsonObjectbuilder.add("access_token", "abc123");
        jsonObjectbuilder.add("expires_in", 60L);

        try {
            OIDCTokens.parse(jsonObjectbuilder.build());
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage().startsWith("Couldn't parse ID token: Invalid unsecured/JWS/JWE header:")).isTrue();
        }
    }

    @Test
    public void testParseNullIDToken()
            throws OAuth2JSONParseException {

        JsonObjectBuilder jsonObjectbuilder = Json.createObjectBuilder();
        jsonObjectbuilder.addNull("id_token"); // invalid
        jsonObjectbuilder.add("token_type", "Bearer");
        jsonObjectbuilder.add("access_token", "abc123");
        jsonObjectbuilder.add("expires_in", 60L);

        OIDCTokens oidcTokens = OIDCTokens.parse(jsonObjectbuilder.build());

        assertThat(oidcTokens.getIDToken()).isNull();
        assertThat(oidcTokens.getIDTokenString()).isNull();

        assertThat(oidcTokens.getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(oidcTokens.getAccessToken().getLifetime()).isEqualTo(60L);
        assertThat(oidcTokens.getAccessToken().getType()).isEqualTo(AccessTokenType.BEARER);
    }

    @Test
    public void testCastFromTokens() {

        AccessToken accessToken = new BearerAccessToken(60L, Scope.parse("openid email"));
        RefreshToken refreshToken = new RefreshToken();

        Tokens tokens = new OIDCTokens(ID_TOKEN, accessToken, refreshToken);

        OIDCTokens oidcTokens = tokens.toOIDCTokens();

        assertThat(oidcTokens).isEqualTo(tokens);
    }
}
