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
package be.atbash.ee.oauth2.sdk;


import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.token.AccessToken;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.oauth2.sdk.token.RefreshToken;
import be.atbash.ee.oauth2.sdk.token.Tokens;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests access token response serialisation and parsing.
 */
public class AccessTokenResponseTest {

    @Test
    public void testConstructor()
            throws OAuth2JSONParseException {

        Tokens tokens = new Tokens(new BearerAccessToken(), new RefreshToken());
        AccessTokenResponse response = new AccessTokenResponse(tokens);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getTokens().getAccessToken()).isEqualTo(tokens.getAccessToken());
        assertThat(response.getTokens().getBearerAccessToken()).isEqualTo(tokens.getAccessToken());
        assertThat(response.getTokens().getRefreshToken()).isEqualTo(tokens.getRefreshToken());
        assertThat(response.getCustomParameters().isEmpty()).isTrue();
        assertThat(response.getCustomParams().isEmpty()).isTrue();

        HTTPResponse httpResponse = response.toHTTPResponse();
        response = AccessTokenResponse.parse(httpResponse);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getTokens().getAccessToken()).isEqualTo(tokens.getAccessToken());
        assertThat(response.getTokens().getBearerAccessToken()).isEqualTo(tokens.getAccessToken());
        assertThat(response.getTokens().getRefreshToken()).isEqualTo(tokens.getRefreshToken());
        assertThat(response.getCustomParameters().isEmpty()).isTrue();
        assertThat(response.getCustomParams().isEmpty()).isTrue();
    }

    @Test
    public void testConstructorMinimal()
            throws OAuth2JSONParseException {

        Tokens tokens = new Tokens(new BearerAccessToken(), null);

        AccessTokenResponse response = new AccessTokenResponse(tokens, null);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getTokens().getAccessToken()).isEqualTo(tokens.getAccessToken());
        assertThat(response.getTokens().getBearerAccessToken()).isEqualTo(tokens.getAccessToken());
        assertThat(response.getTokens().getRefreshToken()).isNull();
        assertThat(response.getCustomParameters().isEmpty()).isTrue();
        assertThat(response.getCustomParams().isEmpty()).isTrue();

        HTTPResponse httpResponse = response.toHTTPResponse();
        response = AccessTokenResponse.parse(httpResponse);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getTokens().getAccessToken()).isEqualTo(tokens.getAccessToken());
        assertThat(response.getTokens().getBearerAccessToken()).isEqualTo(tokens.getAccessToken());
        assertThat(response.getTokens().getRefreshToken()).isNull();
        assertThat(response.getCustomParameters().isEmpty()).isTrue();
        assertThat(response.getCustomParams().isEmpty()).isTrue();
    }

    @Test
    public void testConstructorWithCustomParams()
            throws OAuth2JSONParseException {

        Tokens tokens = new Tokens(new BearerAccessToken(), null);
        Map<String, Object> customParams = new HashMap<>();
        customParams.put("sub_sid", "abc");

        AccessTokenResponse response = new AccessTokenResponse(tokens, customParams);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getTokens().getAccessToken()).isEqualTo(tokens.getAccessToken());
        assertThat(response.getTokens().getBearerAccessToken()).isEqualTo(tokens.getAccessToken());
        assertThat(response.getTokens().getRefreshToken()).isNull();
        assertThat((String) response.getCustomParameters().get("sub_sid")).isEqualTo("abc");
        assertThat((String) response.getCustomParams().get("sub_sid")).isEqualTo("abc");

        HTTPResponse httpResponse = response.toHTTPResponse();
        response = AccessTokenResponse.parse(httpResponse);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getTokens().getAccessToken()).isEqualTo(tokens.getAccessToken());
        assertThat(response.getTokens().getBearerAccessToken()).isEqualTo(tokens.getAccessToken());
        assertThat(response.getTokens().getRefreshToken()).isNull();
        assertThat((String) response.getCustomParameters().get("sub_sid")).isEqualTo("abc");
        assertThat((String) response.getCustomParams().get("sub_sid")).isEqualTo("abc");
    }

    @Test
    public void testParseFromHTTPResponseWithCustomParams()
            throws Exception {

        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpResponse.setCacheControl("no-store");
        httpResponse.setPragma("no-cache");

        JsonObjectBuilder builder = Json.createObjectBuilder();

        String accessTokenString = "SlAV32hkKG";
        builder.add("access_token", accessTokenString);

        builder.add("token_type", "Bearer");

        String refreshTokenString = "8xLOxBtZp8";
        builder.add("refresh_token", refreshTokenString);

        long exp = 3600;
        builder.add("expires_in", exp);

        builder.add("sub_sid", "abc");
        builder.add("priority", 10);

        httpResponse.setContent(builder.build().toString());


        AccessTokenResponse atr = AccessTokenResponse.parse(httpResponse);

        assertThat(atr.indicatesSuccess()).isTrue();

        AccessToken accessToken = atr.getTokens().getAccessToken();
        assertThat(accessToken.getValue()).isEqualTo(accessTokenString);

        BearerAccessToken bearerAccessToken = atr.getTokens().getBearerAccessToken();
        assertThat(bearerAccessToken.getValue()).isEqualTo(accessTokenString);

        assertThat(accessToken.getLifetime()).isEqualTo(exp);
        assertThat(accessToken.getScope()).isNull();

        RefreshToken refreshToken = atr.getTokens().getRefreshToken();
        assertThat(refreshToken.getValue()).isEqualTo(refreshTokenString);

        // Custom param
        assertThat((String) atr.getCustomParameters().get("sub_sid")).isEqualTo("abc");
        assertThat((String) atr.getCustomParams().get("sub_sid")).isEqualTo("abc");
        assertThat(((Number) atr.getCustomParameters().get("priority")).intValue()).isEqualTo(10);
        assertThat(((Number) atr.getCustomParams().get("priority")).intValue()).isEqualTo(10);
        assertThat(atr.getCustomParameters()).hasSize(2);
        assertThat(atr.getCustomParams()).hasSize(2);

        // Test pair getter
        Tokens pair = atr.getTokens();
        assertThat(pair.getAccessToken()).isEqualTo(accessToken);
        assertThat(pair.getRefreshToken()).isEqualTo(refreshToken);

        httpResponse = atr.toHTTPResponse();

        assertThat(httpResponse.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_JSON.toString());
        assertThat(httpResponse.getCacheControl()).isEqualTo("no-store");
        assertThat(httpResponse.getPragma()).isEqualTo("no-cache");

        JsonObject jsonObject = httpResponse.getContentAsJSONObject();

        assertThat(jsonObject.getString("access_token")).isEqualTo(accessTokenString);
        assertThat(jsonObject.getString("token_type")).isEqualTo("Bearer");
        assertThat(jsonObject.getString("refresh_token")).isEqualTo(refreshTokenString);
        assertThat(jsonObject.getJsonNumber("expires_in").longValue()).isEqualTo(3600L);

        // Custom param
        assertThat(jsonObject.getString("sub_sid")).isEqualTo("abc");
        assertThat(jsonObject.getJsonNumber("priority").intValue()).isEqualTo(10);
    }

    @Test
    public void testParseFromAltHTTPResponse()
            throws Exception {

        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpResponse.setCacheControl("no-store");
        httpResponse.setPragma("no-cache");

        JsonObjectBuilder builder = Json.createObjectBuilder();
        String accessTokenString = "SlAV32hkKG";
        builder.add("access_token", accessTokenString);

        builder.add("token_type", "bearer");

        httpResponse.setContent(builder.build().toString());

        AccessTokenResponse atr = AccessTokenResponse.parse(httpResponse);

        assertThat(atr.indicatesSuccess()).isTrue();
        AccessToken accessToken = atr.getTokens().getAccessToken();
        assertThat(accessToken.getValue()).isEqualTo(accessTokenString);
        BearerAccessToken bearerAccessToken = atr.getTokens().getBearerAccessToken();
        assertThat(bearerAccessToken.getValue()).isEqualTo(accessTokenString);
        assertThat(accessToken.getScope()).isNull();

        Tokens tokens = atr.getTokens();
        assertThat(tokens.getAccessToken()).isEqualTo(accessToken);

        httpResponse = atr.toHTTPResponse();

        assertThat(httpResponse.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_JSON.toString());
        assertThat(httpResponse.getCacheControl()).isEqualTo("no-store");
        assertThat(httpResponse.getPragma()).isEqualTo("no-cache");

        JsonObject jsonObject = httpResponse.getContentAsJSONObject();

        assertThat(jsonObject.getString("access_token")).isEqualTo(accessTokenString);
        assertThat(jsonObject.getString("token_type")).isEqualTo("Bearer");
    }

    @Test
    public void testParseJSONObjectNoSideEffects()
            throws Exception {

        // {
        //   "access_token":"2YotnFZFEjr1zCsicMWpAA",
        //   "token_type":"Bearer",
        //   "expires_in":3600,
        //   "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
        //   "example_parameter":"example_value"
        // }

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("access_token", "2YotnFZFEjr1zCsicMWpAA");
        builder.add("token_type", "Bearer");
        builder.add("expires_in", 3600);
        builder.add("refresh_token", "tGzv3JOkF0XG5Qx2TlKWIA");
        builder.add("example_parameter", "example_value");

        JsonObject jsonObject = builder.build();

        Set<String> keys = new HashSet<>(jsonObject.keySet());

        AccessTokenResponse response = AccessTokenResponse.parse(jsonObject);
        assertThat(response.getTokens().getBearerAccessToken().getValue()).isEqualTo("2YotnFZFEjr1zCsicMWpAA");
        assertThat(response.getTokens().getBearerAccessToken().getLifetime()).isEqualTo(3600L);
        assertThat(response.getTokens().getRefreshToken().getValue()).isEqualTo("tGzv3JOkF0XG5Qx2TlKWIA");
        assertThat(response.getCustomParameters().get("example_parameter")).isEqualTo("example_value");
        assertThat(response.getCustomParameters()).hasSize(1);

        assertThat(jsonObject.keySet()).isEqualTo(keys);
    }
}
