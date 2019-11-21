/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package be.atbash.ee.oauth2.sdk;


import be.atbash.ee.oauth2.sdk.auth.X509CertificateConfirmation;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.*;
import be.atbash.ee.oauth2.sdk.token.AccessTokenType;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.util.Arrays;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the token introspection success response class.
 */
public class TokenIntrospectionSuccessResponseTest {

    @Test
    public void testExample()
            throws Exception {

        HTTPResponse httpResponse = new HTTPResponse(200);
        httpResponse.setContentType("application/json");
        String json =
                "{\n" +
                        " \"active\": true,\n" +
                        " \"client_id\": \"l238j323ds-23ij4\",\n" +
                        " \"username\": \"jdoe\",\n" +
                        " \"scope\": \"read write dolphin\",\n" +
                        " \"sub\": \"Z5O3upPC88QrAjx00dis\",\n" +
                        " \"aud\": \"https://protected.example.net/resource\",\n" +
                        " \"iss\": \"https://server.example.com/\",\n" +
                        " \"exp\": 1419356238,\n" +
                        " \"iat\": 1419350238,\n" +
                        " \"extension_field\": \"twenty-seven\"\n" +
                        "}";
        httpResponse.setContent(json);

        TokenIntrospectionSuccessResponse response = TokenIntrospectionSuccessResponse.parse(httpResponse);
        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.isActive()).isTrue();
        assertThat(response.getClientID()).isEqualTo(new ClientID("l238j323ds-23ij4"));
        assertThat(response.getUsername()).isEqualTo("jdoe");
        assertThat(response.getScope()).isEqualTo(Scope.parse("read write dolphin"));
        assertThat(response.getSubject()).isEqualTo(new Subject("Z5O3upPC88QrAjx00dis"));
        assertThat(response.getAudience().get(0)).isEqualTo(new Audience("https://protected.example.net/resource"));
        assertThat(response.getAudience()).hasSize(1);
        assertThat(response.getIssuer()).isEqualTo(new Issuer("https://server.example.com/"));
        assertThat(response.getExpirationTime()).isEqualTo(DateUtils.fromSecondsSinceEpoch(1419356238L));
        assertThat(response.getIssueTime()).isEqualTo(DateUtils.fromSecondsSinceEpoch(1419350238L));
        assertThat(response.getX509CertificateSHA256Thumbprint()).isNull();
        assertThat(response.getX509CertificateConfirmation()).isNull();
        assertThat(response.toJSONObject().getString("extension_field")).isEqualTo("twenty-seven");

        httpResponse = response.toHTTPResponse();

        response = TokenIntrospectionSuccessResponse.parse(httpResponse);
        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.isActive()).isTrue();
        assertThat(response.getClientID()).isEqualTo(new ClientID("l238j323ds-23ij4"));
        assertThat(response.getUsername()).isEqualTo("jdoe");
        assertThat(response.getScope()).isEqualTo(Scope.parse("read write dolphin"));
        assertThat(response.getSubject()).isEqualTo(new Subject("Z5O3upPC88QrAjx00dis"));
        assertThat(response.getAudience().get(0)).isEqualTo(new Audience("https://protected.example.net/resource"));
        assertThat(response.getAudience()).hasSize(1);
        assertThat(response.getIssuer()).isEqualTo(new Issuer("https://server.example.com/"));
        assertThat(response.getExpirationTime()).isEqualTo(DateUtils.fromSecondsSinceEpoch(1419356238L));
        assertThat(response.getIssueTime()).isEqualTo(DateUtils.fromSecondsSinceEpoch(1419350238L));
        assertThat(response.getX509CertificateSHA256Thumbprint()).isNull();
        assertThat(response.getX509CertificateConfirmation()).isNull();
        assertThat(response.toJSONObject().getString("extension_field")).isEqualTo("twenty-seven");
    }

    @Test
    public void testBuilderMinimal_active()
            throws Exception {

        TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
                .build();

        assertThat(response.isActive()).isTrue();
        assertThat(response.getScope()).isNull();
        assertThat(response.getClientID()).isNull();
        assertThat(response.getUsername()).isNull();
        assertThat(response.getTokenType()).isNull();
        assertThat(response.getExpirationTime()).isNull();
        assertThat(response.getIssueTime()).isNull();
        assertThat(response.getNotBeforeTime()).isNull();
        assertThat(response.getSubject()).isNull();
        assertThat(response.getAudience()).isNull();
        assertThat(response.getIssuer()).isNull();
        assertThat(response.getJWTID()).isNull();
        assertThat(response.getX509CertificateSHA256Thumbprint()).isNull();
        assertThat(response.getX509CertificateConfirmation()).isNull();

        JsonObject jsonObject = response.toJSONObject();
        assertThat(jsonObject.getBoolean("active")).isTrue();
        assertThat(jsonObject).hasSize(1);

        HTTPResponse httpResponse = response.toHTTPResponse();

        assertThat(httpResponse.getStatusCode()).isEqualTo(200);
        assertThat(httpResponse.getContentType().getBaseType()).isEqualTo(CommonContentTypes.APPLICATION_JSON.getBaseType());
        jsonObject = httpResponse.getContentAsJSONObject();
        assertThat(jsonObject.getBoolean("active")).isTrue();
        assertThat(jsonObject).hasSize(1);

        response = TokenIntrospectionSuccessResponse.parse(httpResponse);

        assertThat(response.isActive()).isTrue();
        assertThat(response.getScope()).isNull();
        assertThat(response.getClientID()).isNull();
        assertThat(response.getUsername()).isNull();
        assertThat(response.getTokenType()).isNull();
        assertThat(response.getExpirationTime()).isNull();
        assertThat(response.getIssueTime()).isNull();
        assertThat(response.getNotBeforeTime()).isNull();
        assertThat(response.getSubject()).isNull();
        assertThat(response.getAudience()).isNull();
        assertThat(response.getIssuer()).isNull();
        assertThat(response.getJWTID()).isNull();
        assertThat(response.getX509CertificateSHA256Thumbprint()).isNull();
        assertThat(response.getX509CertificateConfirmation()).isNull();
    }

    @Test
    public void testBuilderMinimal_inactive()
            throws Exception {

        TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(false)
                .build();

        assertThat(response.isActive()).isFalse();
        assertThat(response.getScope()).isNull();
        assertThat(response.getClientID()).isNull();
        assertThat(response.getUsername()).isNull();
        assertThat(response.getTokenType()).isNull();
        assertThat(response.getExpirationTime()).isNull();
        assertThat(response.getIssueTime()).isNull();
        assertThat(response.getNotBeforeTime()).isNull();
        assertThat(response.getSubject()).isNull();
        assertThat(response.getAudience()).isNull();
        assertThat(response.getIssuer()).isNull();
        assertThat(response.getJWTID()).isNull();
        assertThat(response.getX509CertificateSHA256Thumbprint()).isNull();
        assertThat(response.getX509CertificateConfirmation()).isNull();

        JsonObject jsonObject = response.toJSONObject();
        assertThat(jsonObject.getBoolean("active")).isFalse();
        assertThat(jsonObject).hasSize(1);

        HTTPResponse httpResponse = response.toHTTPResponse();

        assertThat(httpResponse.getStatusCode()).isEqualTo(200);
        assertThat(httpResponse.getContentType().getBaseType()).isEqualTo(CommonContentTypes.APPLICATION_JSON.getBaseType());
        jsonObject = httpResponse.getContentAsJSONObject();
        assertThat(jsonObject.getBoolean("active")).isFalse();
        assertThat(jsonObject).hasSize(1);

        response = TokenIntrospectionSuccessResponse.parse(httpResponse);

        assertThat(response.isActive()).isFalse();
        assertThat(response.getScope()).isNull();
        assertThat(response.getClientID()).isNull();
        assertThat(response.getUsername()).isNull();
        assertThat(response.getTokenType()).isNull();
        assertThat(response.getExpirationTime()).isNull();
        assertThat(response.getIssueTime()).isNull();
        assertThat(response.getNotBeforeTime()).isNull();
        assertThat(response.getSubject()).isNull();
        assertThat(response.getAudience()).isNull();
        assertThat(response.getIssuer()).isNull();
        assertThat(response.getJWTID()).isNull();
        assertThat(response.getScope()).isNull();
        assertThat(response.getClientID()).isNull();
        assertThat(response.getUsername()).isNull();
        assertThat(response.getTokenType()).isNull();
        assertThat(response.getExpirationTime()).isNull();
        assertThat(response.getIssueTime()).isNull();
        assertThat(response.getNotBeforeTime()).isNull();
        assertThat(response.getSubject()).isNull();
        assertThat(response.getAudience()).isNull();
        assertThat(response.getIssuer()).isNull();
        assertThat(response.getJWTID()).isNull();
        assertThat(response.getX509CertificateSHA256Thumbprint()).isNull();
        assertThat(response.getX509CertificateConfirmation()).isNull();
    }

    @Test
    public void testBuilder_complete()
            throws Exception {

        TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
                .scope(Scope.parse("read write"))
                .clientID(new ClientID("123"))
                .username("alice")
                .tokenType(AccessTokenType.BEARER)
                .expirationTime(DateUtils.fromSecondsSinceEpoch(102030L))
                .issueTime(DateUtils.fromSecondsSinceEpoch(203040L))
                .notBeforeTime(DateUtils.fromSecondsSinceEpoch(304050L))
                .subject(new Subject("alice.wonderland"))
                .audience(Audience.create("456", "789"))
                .issuer(new Issuer("https://c2id.com"))
                .jwtID(new JWTID("xyz"))
                .x509CertificateConfirmation(new X509CertificateConfirmation(new Base64URLValue("abc")))
                .parameter("ip", "10.20.30.40")
                .build();

        assertThat(response.isActive()).isTrue();
        assertThat(response.getScope()).isEqualTo(Scope.parse("read write"));
        assertThat(response.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(response.getUsername()).isEqualTo("alice");
        assertThat(response.getTokenType()).isEqualTo(AccessTokenType.BEARER);
        assertThat(response.getExpirationTime()).isEqualTo(DateUtils.fromSecondsSinceEpoch(102030L));
        assertThat(response.getIssueTime()).isEqualTo(DateUtils.fromSecondsSinceEpoch(203040L));
        assertThat(response.getNotBeforeTime()).isEqualTo(DateUtils.fromSecondsSinceEpoch(304050L));
        assertThat(response.getSubject()).isEqualTo(new Subject("alice.wonderland"));
        assertThat(response.getAudience()).isEqualTo(Audience.create("456", "789"));
        assertThat(response.getIssuer()).isEqualTo(new Issuer("https://c2id.com"));
        assertThat(response.getJWTID()).isEqualTo(new JWTID("xyz"));
        assertThat(response.getX509CertificateConfirmation().getValue()).isEqualTo(new Base64URLValue("abc"));
        assertThat(response.toJSONObject().getString("ip")).isEqualTo("10.20.30.40");

        assertThat(response.toJSONObject()).hasSize(14);

        HTTPResponse httpResponse = response.toHTTPResponse();

        assertThat(httpResponse.getStatusCode()).isEqualTo(200);
        assertThat(httpResponse.getContentType().toString()).isEqualTo("application/json; charset=UTF-8");

        response = TokenIntrospectionSuccessResponse.parse(httpResponse);

        assertThat(response.isActive()).isTrue();
        assertThat(response.getScope()).isEqualTo(Scope.parse("read write"));
        assertThat(response.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(response.getUsername()).isEqualTo("alice");
        assertThat(response.getTokenType()).isEqualTo(AccessTokenType.BEARER);
        assertThat(response.getExpirationTime()).isEqualTo(DateUtils.fromSecondsSinceEpoch(102030L));
        assertThat(response.getIssueTime()).isEqualTo(DateUtils.fromSecondsSinceEpoch(203040L));
        assertThat(response.getNotBeforeTime()).isEqualTo(DateUtils.fromSecondsSinceEpoch(304050L));
        assertThat(response.getSubject()).isEqualTo(new Subject("alice.wonderland"));
        assertThat(response.getAudience()).isEqualTo(Audience.create("456", "789"));
        assertThat(response.getIssuer()).isEqualTo(new Issuer("https://c2id.com"));
        assertThat(response.getJWTID()).isEqualTo(new JWTID("xyz"));
        assertThat(response.getX509CertificateConfirmation().getValue()).isEqualTo(new Base64URLValue("abc"));
        assertThat(response.toJSONObject().getString("ip")).isEqualTo("10.20.30.40");

        assertThat(response.toJSONObject()).hasSize(14);
    }

    @Test
    public void testBuilder_deprecatedCnfX5t()
            throws Exception {

        TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
                .scope(Scope.parse("read write"))
                .x509CertificateSHA256Thumbprint(new Base64URLValue("abc"))
                .build();

        assertThat(response.isActive()).isTrue();
        assertThat(response.getScope()).isEqualTo(Scope.parse("read write"));
        assertThat(response.getX509CertificateSHA256Thumbprint()).isEqualTo(new Base64URLValue("abc"));

        assertThat(response.toJSONObject()).hasSize(3);

        HTTPResponse httpResponse = response.toHTTPResponse();

        assertThat(httpResponse.getStatusCode()).isEqualTo(200);
        assertThat(httpResponse.getContentType().toString()).isEqualTo("application/json; charset=UTF-8");

        response = TokenIntrospectionSuccessResponse.parse(httpResponse);

        assertThat(response.isActive()).isTrue();
        assertThat(response.getScope()).isEqualTo(Scope.parse("read write"));
        assertThat(response.getX509CertificateSHA256Thumbprint()).isEqualTo(new Base64URLValue("abc"));

        assertThat(response.toJSONObject()).hasSize(3);
    }

    @Test
    public void testMutualTLSExample()
            throws Exception {

        String json = "{" +
                "  \"active\": true," +
                "  \"iss\": \"https://server.example.com\"," +
                "  \"sub\": \"ty.webb@example.com\"," +
                "  \"exp\": 1493726400," +
                "  \"nbf\": 1493722800," +
                "  \"cnf\":{" +
                "    \"x5t#S256\": \"bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2\"" +
                "  }" +
                "}";

        JsonObject jsonObject = JSONObjectUtils.parse(json);

        TokenIntrospectionSuccessResponse response = TokenIntrospectionSuccessResponse.parse(jsonObject);
        assertThat(response.isActive()).isTrue();
        assertThat(response.getIssuer()).isEqualTo(new Issuer("https://server.example.com"));
        assertThat(response.getSubject()).isEqualTo(new Subject("ty.webb@example.com"));
        assertThat(response.getExpirationTime()).isEqualTo(new Date(1493726400 * 1000L));
        assertThat(response.getNotBeforeTime()).isEqualTo(new Date(1493722800 * 1000L));
        assertThat(response.getX509CertificateConfirmation().getValue()).isEqualTo(new Base64URLValue("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"));
        assertThat(response.getX509CertificateSHA256Thumbprint()).isEqualTo(new Base64URLValue("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"));
    }

    @Test
    public void testCopyConstructorBuilder() {

        TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
                .issuer(new Issuer("https://c2id.com"))
                .subject(new Subject("alice"))
                .scope(new Scope("openid", "email"))
                .build();

        TokenIntrospectionSuccessResponse copy = new TokenIntrospectionSuccessResponse.Builder(response)
                .build();

        assertThat(copy.isActive()).isEqualTo(response.isActive());
        assertThat(copy.getIssuer()).isEqualTo(response.getIssuer());
        assertThat(copy.getSubject()).isEqualTo(response.getSubject());
        assertThat(copy.getScope()).isEqualTo(response.getScope());

        assertThat(copy.toJSONObject()).isEqualTo(response.toJSONObject());
    }

    @Test
    public void testGetParameters()  {

        TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
                .issuer(new Issuer("https://c2id.com"))
                .subject(new Subject("alice"))
                .scope(new Scope("openid", "email"))
                .build();

        JsonObject parameters = response.getParameters();
        assertThat(parameters.getBoolean("active")).isTrue();
        assertThat(parameters.getString( "iss")).isEqualTo(response.getIssuer().getValue());
        assertThat(parameters.getString( "sub")).isEqualTo(response.getSubject().getValue());
        assertThat(parameters.getString( "scope")).isEqualTo(response.getScope().toString());
        assertThat(parameters).hasSize(4);
    }

    @Test
    public void testGetStringParameter() {

        Date iat = new Date();

        TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
                .issuer(new Issuer("https://c2id.com"))
                .issueTime(iat)
                .subject(new Subject("alice"))
                .scope(new Scope("openid", "email"))
                .build();

        assertThat(response.getStringParameter("sub")).isEqualTo("alice");
        assertThat(response.getStringParameter("iat")).isNull(); // not string
    }

    @Test
    public void testGetBooleanParameter() throws OAuth2JSONParseException {

        Date iat = new Date();

        TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
                .issuer(new Issuer("https://c2id.com"))
                .issueTime(iat)
                .subject(new Subject("alice"))
                .scope(new Scope("openid", "email"))
                .build();

        assertThat(response.getBooleanParameter("active")).isTrue();

        try {
            response.getBooleanParameter("iat");
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Unexpected type of JSON object member with key \"iat\"");
        }
    }

    @Test
    public void testGetNumberParameter() {

        Date iat = new Date(new Date().getTime() / 1000 * 1000);

        TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
                .issuer(new Issuer("https://c2id.com"))
                .issueTime(iat)
                .subject(new Subject("alice"))
                .scope(new Scope("openid", "email"))
                .build();

        assertThat(response.getNumberParameter("iat").longValue()).isEqualTo(iat.getTime() / 1000L);

        assertThat(response.getNumberParameter("sub")).isNull(); // invalid number
    }

    @Test
    public void testGetStringListParameter() {

        TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
                .issuer(new Issuer("https://c2id.com"))
                .subject(new Subject("alice"))
                .scope(new Scope("openid", "email"))
                .parameter("claims", Arrays.asList("email", "email_verified"))
                .build();

        assertThat(response.getStringListParameter("claims")).isEqualTo(Arrays.asList("email", "email_verified"));

        assertThat(response.getStringListParameter("sub")).isNull(); // invalid string list
    }

    @Test
    public void testGetJSONObjectParameter() {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("ip", "192.168.0.1");

        JsonObject data = builder.build();
        TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
                .issuer(new Issuer("https://c2id.com"))
                .subject(new Subject("alice"))
                .scope(new Scope("openid", "email"))
                .parameter("data", data)
                .build();

        assertThat(response.getJSONObjectParameter("data")).isEqualTo(data);

        assertThat(response.getJSONObjectParameter("sub")).isNull(); // invalid parameter
    }
}
