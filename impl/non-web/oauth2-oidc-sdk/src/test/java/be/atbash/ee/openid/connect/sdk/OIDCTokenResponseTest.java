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


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.oauth2.sdk.token.RefreshToken;
import be.atbash.ee.openid.connect.sdk.token.OIDCTokens;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.json.JsonObject;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the OpenID Connect token response.
 */
public class OIDCTokenResponseTest {


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
    public void testWithIDTokenJWT()
            throws Exception {

        OIDCTokens tokens = new OIDCTokens(ID_TOKEN, new BearerAccessToken("abc123"), new RefreshToken("def456"));

        OIDCTokenResponse response = new OIDCTokenResponse(tokens);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getOIDCTokens().getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(response.getOIDCTokens().getRefreshToken().getValue()).isEqualTo("def456");
        assertThat(response.getOIDCTokens().getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getOIDCTokens().getIDToken().serialize()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getCustomParameters().isEmpty()).isTrue();

        HTTPResponse httpResponse = response.toHTTPResponse();

        response = OIDCTokenResponse.parse(httpResponse);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getOIDCTokens().getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(response.getOIDCTokens().getRefreshToken().getValue()).isEqualTo("def456");
        assertThat(response.getOIDCTokens().getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getOIDCTokens().getIDToken().serialize()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testWithIDTokenJWTAndCustomParams()
            throws Exception {

        OIDCTokens tokens = new OIDCTokens(ID_TOKEN, new BearerAccessToken("abc123"), new RefreshToken("def456"));
        Map<String, Object> customParams = new HashMap<>();
        customParams.put("sub_sid", "abc");
        customParams.put("priority", 10);

        OIDCTokenResponse response = new OIDCTokenResponse(tokens, customParams);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getOIDCTokens().getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(response.getOIDCTokens().getRefreshToken().getValue()).isEqualTo("def456");
        assertThat(response.getOIDCTokens().getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getOIDCTokens().getIDToken().serialize()).isEqualTo(ID_TOKEN_STRING);
        assertThat((String) response.getCustomParameters().get("sub_sid")).isEqualTo("abc");
        assertThat(((Number) response.getCustomParameters().get("priority")).intValue()).isEqualTo(10);
        assertThat(response.getCustomParameters()).hasSize(2);

        HTTPResponse httpResponse = response.toHTTPResponse();

        response = OIDCTokenResponse.parse(httpResponse);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getOIDCTokens().getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(response.getOIDCTokens().getRefreshToken().getValue()).isEqualTo("def456");
        assertThat(response.getOIDCTokens().getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getOIDCTokens().getIDToken().serialize()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getCustomParameters().get("sub_sid").toString()).isEqualTo("abc");
        assertThat(((Number) response.getCustomParameters().get("priority")).intValue()).isEqualTo(10);
        assertThat(response.getCustomParameters()).hasSize(2);
    }

    @Test
    public void testWithIDTokenString()
            throws Exception {

        OIDCTokens tokens = new OIDCTokens(ID_TOKEN_STRING, new BearerAccessToken("abc123"), new RefreshToken("def456"));

        OIDCTokenResponse response = new OIDCTokenResponse(tokens);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getOIDCTokens().getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(response.getOIDCTokens().getRefreshToken().getValue()).isEqualTo("def456");
        assertThat(response.getOIDCTokens().getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getOIDCTokens().getIDToken().serialize()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getCustomParameters().isEmpty()).isTrue();

        HTTPResponse httpResponse = response.toHTTPResponse();

        response = OIDCTokenResponse.parse(httpResponse);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getOIDCTokens().getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(response.getOIDCTokens().getRefreshToken().getValue()).isEqualTo("def456");
        assertThat(response.getOIDCTokens().getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getOIDCTokens().getIDToken().serialize()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testWithIDTokenStringAndCustomParams()
            throws Exception {

        OIDCTokens tokens = new OIDCTokens(ID_TOKEN_STRING, new BearerAccessToken("abc123"), new RefreshToken("def456"));
        Map<String, Object> customParams = new HashMap<>();
        customParams.put("sub_sid", "abc");
        customParams.put("priority", 10);

        OIDCTokenResponse response = new OIDCTokenResponse(tokens, customParams);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getOIDCTokens().getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(response.getOIDCTokens().getRefreshToken().getValue()).isEqualTo("def456");
        assertThat(response.getOIDCTokens().getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getOIDCTokens().getIDToken().serialize()).isEqualTo(ID_TOKEN_STRING);
        assertThat((String) response.getCustomParameters().get("sub_sid")).isEqualTo("abc");
        assertThat(((Number) response.getCustomParameters().get("priority")).intValue()).isEqualTo(10);
        assertThat(response.getCustomParameters()).hasSize(2);

        HTTPResponse httpResponse = response.toHTTPResponse();

        response = OIDCTokenResponse.parse(httpResponse);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getOIDCTokens().getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(response.getOIDCTokens().getRefreshToken().getValue()).isEqualTo("def456");
        assertThat(response.getOIDCTokens().getIDTokenString()).isEqualTo(ID_TOKEN_STRING);
        assertThat(response.getOIDCTokens().getIDToken().serialize()).isEqualTo(ID_TOKEN_STRING);
        assertThat((String) response.getCustomParameters().get("sub_sid")).isEqualTo("abc");
        assertThat(((Number) response.getCustomParameters().get("priority")).intValue()).isEqualTo(10);
        assertThat(response.getCustomParameters()).hasSize(2);
    }

    @Test
    public void testWithoutIDToken()
            throws Exception {

        OIDCTokens tokens = new OIDCTokens(new BearerAccessToken("abc123"), new RefreshToken("def456"));
        OIDCTokenResponse response = new OIDCTokenResponse(tokens);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getOIDCTokens().getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(response.getOIDCTokens().getRefreshToken().getValue()).isEqualTo("def456");
        assertThat(response.getOIDCTokens().getIDToken()).isNull();
        assertThat(response.getOIDCTokens().getIDTokenString()).isNull();

        JsonObject jsonObject = response.toJSONObject().build();
        assertThat(jsonObject.getString("access_token")).isEqualTo(tokens.getAccessToken().getValue());
        assertThat(jsonObject.getString("token_type")).isEqualTo("Bearer");
        assertThat(jsonObject).hasSize(3);


        OIDCTokenResponse parsedResponse = OIDCTokenResponse.parse(jsonObject);
        assertThat(parsedResponse.getOIDCTokens().getAccessToken().getValue()).isEqualTo(tokens.getAccessToken().getValue());
        assertThat(parsedResponse.getOIDCTokens().getRefreshToken().getValue()).isEqualTo(tokens.getRefreshToken().getValue());
        assertThat(parsedResponse.getOIDCTokens().getIDToken()).isNull();
        assertThat(parsedResponse.getOIDCTokens().getIDTokenString()).isNull();
    }

    @Test
    public void testWithInvalidIDTokenString() {

        String invalidIDTokenString = "ey...";
        OIDCTokens tokens = new OIDCTokens(invalidIDTokenString, new BearerAccessToken("abc123"), new RefreshToken("def456"));
        OIDCTokenResponse response = new OIDCTokenResponse(tokens);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getOIDCTokens().getAccessToken().getValue()).isEqualTo("abc123");
        assertThat(response.getOIDCTokens().getRefreshToken().getValue()).isEqualTo("def456");
        assertThat(response.getOIDCTokens().getIDToken()).isNull();
        assertThat(response.getOIDCTokens().getIDTokenString()).isEqualTo(invalidIDTokenString);

        JsonObject jsonObject = response.toJSONObject().build();

        Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                OIDCTokenResponse.parse(jsonObject));

    }
}
