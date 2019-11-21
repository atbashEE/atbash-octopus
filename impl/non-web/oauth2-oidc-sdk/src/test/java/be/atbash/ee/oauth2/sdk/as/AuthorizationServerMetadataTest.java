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

package be.atbash.ee.oauth2.sdk.as;


import be.atbash.ee.langtag.LangTag;
import be.atbash.ee.oauth2.sdk.*;
import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.Test;

import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class AuthorizationServerMetadataTest {

    @Test
    public void testRegisteredParameters() {

        Set<String> paramNames = AuthorizationServerMetadata.getRegisteredParameterNames();

        assertThat(paramNames).contains("issuer");
        assertThat(paramNames).contains("authorization_endpoint");
        assertThat(paramNames).contains("token_endpoint");
        assertThat(paramNames).contains("jwks_uri");
        assertThat(paramNames).contains("registration_endpoint");
        assertThat(paramNames).contains("scopes_supported");
        assertThat(paramNames).contains("response_types_supported");
        assertThat(paramNames).contains("response_modes_supported");
        assertThat(paramNames).contains("grant_types_supported");
        assertThat(paramNames).contains("code_challenge_methods_supported");
        assertThat(paramNames).contains("request_object_endpoint");
        assertThat(paramNames).contains("request_parameter_supported");
        assertThat(paramNames).contains("require_request_uri_registration");
        assertThat(paramNames).contains("pushed_authorization_request_endpoint");
        assertThat(paramNames).contains("request_object_endpoint");
        assertThat(paramNames).contains("request_object_signing_alg_values_supported");
        assertThat(paramNames).contains("request_object_encryption_alg_values_supported");
        assertThat(paramNames).contains("request_object_encryption_enc_values_supported");
        assertThat(paramNames).contains("token_endpoint_auth_methods_supported");
        assertThat(paramNames).contains("token_endpoint_auth_signing_alg_values_supported");
        assertThat(paramNames).contains("service_documentation");
        assertThat(paramNames).contains("ui_locales_supported");
        assertThat(paramNames).contains("op_policy_uri");
        assertThat(paramNames).contains("op_tos_uri");
        assertThat(paramNames).contains("introspection_endpoint");
        assertThat(paramNames).contains("introspection_endpoint_auth_methods_supported");
        assertThat(paramNames).contains("introspection_endpoint_auth_signing_alg_values_supported");
        assertThat(paramNames).contains("revocation_endpoint");
        assertThat(paramNames).contains("revocation_endpoint_auth_methods_supported");
        assertThat(paramNames).contains("revocation_endpoint_auth_signing_alg_values_supported");
        assertThat(paramNames).contains("mtls_endpoint_aliases");
        assertThat(paramNames).contains("tls_client_certificate_bound_access_tokens");
        assertThat(paramNames).contains("authorization_signing_alg_values_supported");
        assertThat(paramNames).contains("authorization_encryption_alg_values_supported");
        assertThat(paramNames).contains("authorization_encryption_enc_values_supported");
        assertThat(paramNames).contains("device_authorization_endpoint");

        assertThat(paramNames).hasSize(36);
    }

    @Test
    public void testParseExample()
            throws Exception {

        String json = "{" +
                " \"issuer\":" +
                "   \"https://server.example.com\"," +
                " \"authorization_endpoint\":" +
                "   \"https://server.example.com/authorize\"," +
                " \"token_endpoint\":" +
                "   \"https://server.example.com/token\"," +
                " \"token_endpoint_auth_methods_supported\":" +
                "   [\"client_secret_basic\", \"private_key_jwt\"]," +
                " \"token_endpoint_auth_signing_alg_values_supported\":" +
                "   [\"RS256\", \"ES256\"]," +
                " \"userinfo_endpoint\":" +
                "   \"https://server.example.com/userinfo\"," +
                " \"jwks_uri\":" +
                "   \"https://server.example.com/jwks.json\"," +
                " \"registration_endpoint\":" +
                "   \"https://server.example.com/register\"," +
                " \"scopes_supported\":" +
                "   [\"openid\", \"profile\", \"email\", \"address\"," +
                "    \"phone\", \"offline_access\"]," +
                " \"response_types_supported\":" +
                "   [\"code\", \"code token\"]," +
                " \"service_documentation\":" +
                "   \"http://server.example.com/service_documentation.html\"," +
                " \"ui_locales_supported\":" +
                "   [\"en-US\", \"en-GB\", \"en-CA\", \"fr-FR\", \"fr-CA\"]" +
                "}";

        AuthorizationServerMetadata as = AuthorizationServerMetadata.parse(json);

        assertThat(as.getIssuer()).isEqualTo(new Issuer("https://server.example.com"));
        assertThat(as.getAuthorizationEndpointURI()).isEqualTo(new URI("https://server.example.com/authorize"));
        assertThat(as.getTokenEndpointURI()).isEqualTo(new URI("https://server.example.com/token"));
        assertThat(as.getTokenEndpointAuthMethods()).isEqualTo(Arrays.asList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.PRIVATE_KEY_JWT));
        assertThat(as.getCustomURIParameter("userinfo_endpoint")).isEqualTo(new URI("https://server.example.com/userinfo"));
        assertThat(as.getJWKSetURI()).isEqualTo(new URI("https://server.example.com/jwks.json"));
        assertThat(as.getRegistrationEndpointURI()).isEqualTo(new URI("https://server.example.com/register"));
        assertThat(as.getScopes()).isEqualTo(new Scope("openid", "profile", "email", "address", "phone", "offline_access"));
        assertThat(as.getResponseTypes()).isEqualTo(Arrays.asList(new ResponseType("code"), new ResponseType("code", "token")));
        assertThat(as.getServiceDocsURI()).isEqualTo(new URI("http://server.example.com/service_documentation.html"));
        assertThat(as.getUILocales()).isEqualTo(Arrays.asList(LangTag.parse("en-US"), LangTag.parse("en-GB"), LangTag.parse("en-CA"), LangTag.parse("fr-FR"), LangTag.parse("fr-CA")));
    }

    @Test
    public void testApplyDefaults() {

        Issuer issuer = new Issuer("https://c2id.com");

        AuthorizationServerMetadata meta = new AuthorizationServerMetadata(issuer);

        meta.applyDefaults();

        List<ResponseMode> responseModes = meta.getResponseModes();
        assertThat(responseModes).contains(ResponseMode.QUERY);
        assertThat(responseModes).contains(ResponseMode.FRAGMENT);
        assertThat(responseModes).hasSize(2);

        List<GrantType> grantTypes = meta.getGrantTypes();
        assertThat(grantTypes).contains(GrantType.AUTHORIZATION_CODE);
        assertThat(grantTypes).contains(GrantType.IMPLICIT);
        assertThat(grantTypes).hasSize(2);

        assertThat(meta.getTokenEndpointAuthMethods()).isEqualTo(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
    }

    @Test
    public void testParseMinimal() throws OAuth2JSONParseException {

        JsonObjectBuilder jsonObject = javax.json.Json.createObjectBuilder();
        jsonObject.add("issuer", "https://c2id.com");

        AuthorizationServerMetadata as = AuthorizationServerMetadata.parse(jsonObject.build().toString());
        assertThat(as.getIssuer()).isEqualTo(new Issuer("https://c2id.com"));
    }

    @Test
    public void testParse_issuerNotURI() {

        JsonObjectBuilder jsonObject = javax.json.Json.createObjectBuilder();
        jsonObject.add("issuer", "a b c");

        try {
            AuthorizationServerMetadata.parse(jsonObject.build().toString());
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Illegal character in path at index 1: a b c");
        }
    }

    @Test
    public void testParse_issuerWithQuery() {

        JsonObjectBuilder jsonObject = javax.json.Json.createObjectBuilder();
        jsonObject.add("issuer", "https://c2id.com?a=b");

        try {
            AuthorizationServerMetadata.parse(jsonObject.build().toString());
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("The issuer URI must be without a query component");
        }
    }

    @Test
    public void testParse_issuerWithFragment() {

        JsonObjectBuilder jsonObject = javax.json.Json.createObjectBuilder();
        jsonObject.add("issuer", "https://c2id.com#abc");

        try {
            AuthorizationServerMetadata.parse(jsonObject.build().toString());
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("The issuer URI must be without a fragment component");
        }
    }

    @Test
    public void testRejectAlgNoneInEndpointJWSAlgs() {

        AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));

        try {
            as.setTokenEndpointJWSAlgs(Collections.singletonList(new JWSAlgorithm("none")));
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The \"none\" algorithm is not accepted");
        }

        try {
            as.setIntrospectionEndpointJWSAlgs(Collections.singletonList(new JWSAlgorithm("none")));
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The \"none\" algorithm is not accepted");
        }

        try {
            as.setRevocationEndpointJWSAlgs(Collections.singletonList(new JWSAlgorithm("none")));
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The \"none\" algorithm is not accepted");
        }
    }

    @Test
    public void testJARM() throws OAuth2JSONParseException {

        AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
        as.applyDefaults();

        assertThat(as.getAuthorizationJWSAlgs()).isNull();
        assertThat(as.getAuthorizationJWEAlgs()).isNull();
        assertThat(as.getAuthorizationJWEEncs()).isNull();

        List<JWSAlgorithm> jwsAlgs = Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);
        as.setAuthorizationJWSAlgs(jwsAlgs);
        assertThat(as.getAuthorizationJWSAlgs()).isEqualTo(jwsAlgs);

        List<JWEAlgorithm> jweAlgs = Arrays.asList(JWEAlgorithm.ECDH_ES, JWEAlgorithm.ECDH_ES_A128KW);
        as.setAuthorizationJWEAlgs(jweAlgs);
        assertThat(as.getAuthorizationJWEAlgs()).isEqualTo(jweAlgs);

        List<EncryptionMethod> jweEncs = Arrays.asList(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM);
        as.setAuthorizationJWEEncs(jweEncs);
        assertThat(as.getAuthorizationJWEEncs()).isEqualTo(jweEncs);

        JsonObject jsonObject = as.toJSONObject().build();

        assertThat(JSONObjectUtils.getStringList(jsonObject, "authorization_signing_alg_values_supported")).isEqualTo(Arrays.asList(JWSAlgorithm.ES256.getName(), JWSAlgorithm.ES384.getName(), JWSAlgorithm.ES512.getName()));

        assertThat(JSONObjectUtils.getStringList(jsonObject, "authorization_encryption_alg_values_supported")).isEqualTo(Arrays.asList(JWEAlgorithm.ECDH_ES.getName(), JWEAlgorithm.ECDH_ES_A128KW.getName()));

        assertThat(JSONObjectUtils.getStringList(jsonObject, "authorization_encryption_enc_values_supported")).isEqualTo(Arrays.asList(EncryptionMethod.A128GCM.getName(), EncryptionMethod.A256GCM.getName()));

        as = AuthorizationServerMetadata.parse(jsonObject.toString());

        assertThat(as.getAuthorizationJWSAlgs()).isEqualTo(jwsAlgs);
        assertThat(as.getAuthorizationJWEAlgs()).isEqualTo(jweAlgs);
        assertThat(as.getAuthorizationJWEEncs()).isEqualTo(jweEncs);
    }

    @Test
    public void testRequestObjectEndpoint() throws OAuth2JSONParseException {

        AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
        as.applyDefaults();
        assertThat(as.getRequestObjectEndpoint()).isNull();

        JsonObject jsonObject = as.toJSONObject().build();
        assertThat(jsonObject.keySet()).doesNotContain("request_object_endpoint");

        URI endpoint = URI.create("https://c2id.com/requests");

        as.setRequestObjectEndpoint(endpoint);

        assertThat(as.getRequestObjectEndpoint()).isEqualTo(endpoint);

        jsonObject = as.toJSONObject().build();
        assertThat(jsonObject.getString("request_object_endpoint")).isEqualTo(endpoint.toString());

        as = AuthorizationServerMetadata.parse(jsonObject);

        assertThat(as.getRequestObjectEndpoint()).isEqualTo(endpoint);
    }

    @Test
    public void testRequestURIParamSupported_defaultFalse() throws ParseException {

        AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
        assertThat(as.supportsRequestURIParam()).isFalse();

        as.applyDefaults();
        assertThat(as.supportsRequestURIParam()).isFalse();

        JsonObject jsonObject = as.toJSONObject().build();
        assertThat(jsonObject.getBoolean("request_uri_parameter_supported")).isFalse();
    }

    @Test
    public void testPAR() throws OAuth2JSONParseException {

        AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));

        assertThat(as.getPushedAuthorizationRequestEndpoint()).isNull();

        as.applyDefaults();
        assertThat(as.getPushedAuthorizationRequestEndpoint()).isNull();

        URI parEndpoint = URI.create("https://c2id.com/par");
        as.setPushedAuthorizationRequestEndpoint(parEndpoint);
        assertThat(as.getPushedAuthorizationRequestEndpoint()).isEqualTo(parEndpoint);

        JsonObject jsonObject = as.toJSONObject().build();
        assertThat(jsonObject.getString("pushed_authorization_request_endpoint")).isEqualTo(parEndpoint.toString());

        as = AuthorizationServerMetadata.parse(jsonObject.toString());
        assertThat(as.getPushedAuthorizationRequestEndpoint()).isEqualTo(parEndpoint);
    }
}
