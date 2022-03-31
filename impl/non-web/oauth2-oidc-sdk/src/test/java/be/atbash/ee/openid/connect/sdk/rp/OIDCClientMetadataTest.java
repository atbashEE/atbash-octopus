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
package be.atbash.ee.openid.connect.sdk.rp;


import be.atbash.ee.oauth2.sdk.GrantType;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.ResponseType;
import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.client.RegistrationError;
import be.atbash.ee.openid.connect.sdk.SubjectType;
import be.atbash.ee.openid.connect.sdk.claims.ACR;
import be.atbash.ee.openid.connect.sdk.id.SectorID;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.mail.internet.InternetAddress;
import java.net.URI;
import java.net.URL;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the OIDC client metadata class.
 */
public class OIDCClientMetadataTest {

    @Test
    public void testRegisteredParameters() {

        Set<String> paramNames = OIDCClientMetadata.getRegisteredParameterNames();

        // Base OAuth 2.0 params
        assertThat(paramNames.contains("redirect_uris")).isTrue();
        assertThat(paramNames.contains("client_name")).isTrue();
        assertThat(paramNames.contains("client_uri")).isTrue();
        assertThat(paramNames.contains("logo_uri")).isTrue();
        assertThat(paramNames.contains("contacts")).isTrue();
        assertThat(paramNames.contains("tos_uri")).isTrue();
        assertThat(paramNames.contains("policy_uri")).isTrue();
        assertThat(paramNames.contains("token_endpoint_auth_method")).isTrue();
        assertThat(paramNames.contains("token_endpoint_auth_signing_alg")).isTrue();
        assertThat(paramNames.contains("scope")).isTrue();
        assertThat(paramNames.contains("grant_types")).isTrue();
        assertThat(paramNames.contains("response_types")).isTrue();
        assertThat(paramNames.contains("jwks_uri")).isTrue();
        assertThat(paramNames.contains("jwks")).isTrue();
        assertThat(paramNames.contains("request_uris")).isTrue();
        assertThat(paramNames.contains("request_object_signing_alg")).isTrue();
        assertThat(paramNames.contains("request_object_encryption_alg")).isTrue();
        assertThat(paramNames.contains("request_object_encryption_enc")).isTrue();
        assertThat(paramNames.contains("software_id")).isTrue();
        assertThat(paramNames.contains("software_version")).isTrue();
        assertThat(paramNames.contains("tls_client_certificate_bound_access_tokens")).isTrue();
        assertThat(paramNames.contains("tls_client_auth_subject_dn")).isTrue();
        assertThat(paramNames.contains("tls_client_auth_san_dns")).isTrue();
        assertThat(paramNames.contains("tls_client_auth_san_uri")).isTrue();
        assertThat(paramNames.contains("tls_client_auth_san_ip")).isTrue();
        assertThat(paramNames.contains("tls_client_auth_san_email")).isTrue();
        assertThat(paramNames.contains("authorization_signed_response_alg")).isTrue();
        assertThat(paramNames.contains("authorization_encrypted_response_enc")).isTrue();
        assertThat(paramNames.contains("authorization_encrypted_response_enc")).isTrue();

        // OIDC specifid params
        assertThat(paramNames.contains("application_type")).isTrue();
        assertThat(paramNames.contains("sector_identifier_uri")).isTrue();
        assertThat(paramNames.contains("subject_type")).isTrue();
        assertThat(paramNames.contains("id_token_signed_response_alg")).isTrue();
        assertThat(paramNames.contains("id_token_encrypted_response_alg")).isTrue();
        assertThat(paramNames.contains("id_token_encrypted_response_enc")).isTrue();
        assertThat(paramNames.contains("userinfo_signed_response_alg")).isTrue();
        assertThat(paramNames.contains("userinfo_encrypted_response_alg")).isTrue();
        assertThat(paramNames.contains("userinfo_encrypted_response_enc")).isTrue();
        assertThat(paramNames.contains("default_max_age")).isTrue();
        assertThat(paramNames.contains("require_auth_time")).isTrue();
        assertThat(paramNames.contains("default_acr_values")).isTrue();
        assertThat(paramNames.contains("initiate_login_uri")).isTrue();
        assertThat(paramNames.contains("post_logout_redirect_uris")).isTrue();
        assertThat(paramNames.contains("frontchannel_logout_uri")).isTrue();
        assertThat(paramNames.contains("frontchannel_logout_session_required")).isTrue();
        assertThat(paramNames.contains("backchannel_logout_uri")).isTrue();
        assertThat(paramNames.contains("backchannel_logout_session_required")).isTrue();

        assertThat(OIDCClientMetadata.getRegisteredParameterNames()).hasSize(47);
    }

    @Test
    public void testParseSpecExample()
            throws Exception {

        String jsonString = "{"
                + "   \"application_type\": \"web\","
                + "   \"redirect_uris\":[\"https://client.example.org/callback\",\"https://client.example.org/callback2\"],"
                + "   \"client_name\": \"My Example\","
                + "   \"logo_uri\": \"https://client.example.org/logo.png\","
                + "   \"subject_type\": \"pairwise\","
                + "   \"sector_identifier_uri\":\"https://other.example.net/file_of_redirect_uris.json\","
                + "   \"token_endpoint_auth_method\": \"client_secret_basic\","
                + "   \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\","
                + "   \"userinfo_encrypted_response_alg\": \"RSA-OAEP-256\","
                + "   \"userinfo_encrypted_response_enc\": \"A128CBC-HS256\","
                + "   \"contacts\": [\"ve7jtb@example.org\", \"mary@example.org\"],"
                + "   \"request_uris\":[\"https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA\"]"
                + "  }";


        JsonObject jsonObject = JSONObjectUtils.parse(jsonString);

        OIDCClientMetadata clientMetadata = OIDCClientMetadata.parse(jsonObject);

        assertThat(clientMetadata.getApplicationType()).isEqualTo(ApplicationType.WEB);

        Set<URI> redirectURIs = clientMetadata.getRedirectionURIs();

        assertThat(redirectURIs.contains(new URI("https://client.example.org/callback"))).isTrue();
        assertThat(redirectURIs.contains(new URI("https://client.example.org/callback2"))).isTrue();
        assertThat(redirectURIs).hasSize(2);

        assertThat(clientMetadata.getName()).isEqualTo("My Example");

        assertThat(clientMetadata.getLogoURI().toString()).isEqualTo(new URL("https://client.example.org/logo.png").toString());

        assertThat(clientMetadata.getSubjectType()).isEqualTo(SubjectType.PAIRWISE);

        assertThat(clientMetadata.getSectorIDURI().toString()).isEqualTo(new URL("https://other.example.net/file_of_redirect_uris.json").toString());

        assertThat(clientMetadata.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        assertThat(clientMetadata.getJWKSetURI().toString()).isEqualTo(new URL("https://client.example.org/my_public_keys.jwks").toString());

        assertThat(clientMetadata.getUserInfoJWEAlg()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(clientMetadata.getUserInfoJWEEnc()).isEqualTo(EncryptionMethod.A128CBC_HS256);

        List<InternetAddress> contacts = clientMetadata.getContacts();

        assertThat(contacts.get(0)).isEqualTo(new InternetAddress("ve7jtb@example.org"));
        assertThat(contacts.get(1)).isEqualTo(new InternetAddress("mary@example.org"));
        assertThat(contacts).hasSize(2);

        Set<URI> requestURIs = clientMetadata.getRequestObjectURIs();

        assertThat(requestURIs.contains(new URI("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"))).isTrue();
        assertThat(requestURIs).hasSize(1);

        assertThat(clientMetadata.getFrontChannelLogoutURI()).isNull();
        assertThat(clientMetadata.requiresFrontChannelLogoutSession()).isFalse();
        assertThat(clientMetadata.getBackChannelLogoutURI()).isNull();
        assertThat(clientMetadata.requiresBackChannelLogoutSession()).isFalse();

        assertThat(clientMetadata.getCustomFields().isEmpty()).isTrue();
    }

    @Test
    public void testGettersAndSetters()
            throws Exception {

        OIDCClientMetadata meta = new OIDCClientMetadata();

        assertThat(meta.getApplicationType()).isNull();
        meta.setApplicationType(ApplicationType.NATIVE);
        assertThat(meta.getApplicationType()).isEqualTo(ApplicationType.NATIVE);

        assertThat(meta.getSubjectType()).isNull();
        meta.setSubjectType(SubjectType.PAIRWISE);
        assertThat(meta.getSubjectType()).isEqualTo(SubjectType.PAIRWISE);

        assertThat(meta.getSectorIDURI()).isNull();
        URI sectorIDURI = new URI("https://example.com/callbacks.json");
        meta.setSectorIDURI(sectorIDURI);
        assertThat(meta.getSectorIDURI().toString()).isEqualTo(sectorIDURI.toString());

        assertThat(meta.getRequestObjectURIs()).isNull();
        Set<URI> requestObjURIs = new HashSet<>();
        requestObjURIs.add(new URI("http://client.com/reqobj"));
        meta.setRequestObjectURIs(requestObjURIs);
        assertThat(meta.getRequestObjectURIs().iterator().next().toString()).isEqualTo("http://client.com/reqobj");
        assertThat(meta.getRequestObjectURIs()).hasSize(1);

        assertThat(meta.getRequestObjectJWSAlg()).isNull();
        meta.setRequestObjectJWSAlg(JWSAlgorithm.HS512);
        assertThat(meta.getRequestObjectJWSAlg()).isEqualTo(JWSAlgorithm.HS512);

        assertThat(meta.getRequestObjectJWEAlg()).isNull();
        meta.setRequestObjectJWEAlg(JWEAlgorithm.A128KW);
        assertThat(meta.getRequestObjectJWEAlg()).isEqualTo(JWEAlgorithm.A128KW);

        assertThat(meta.getRequestObjectJWEEnc()).isNull();
        meta.setRequestObjectJWEEnc(EncryptionMethod.A128GCM);
        assertThat(meta.getRequestObjectJWEEnc()).isEqualTo(EncryptionMethod.A128GCM);

        assertThat(meta.getTokenEndpointAuthJWSAlg()).isNull();
        meta.setTokenEndpointAuthJWSAlg(JWSAlgorithm.HS384);
        assertThat(meta.getTokenEndpointAuthJWSAlg()).isEqualTo(JWSAlgorithm.HS384);

        assertThat(meta.getIDTokenJWSAlg()).isNull();
        meta.setIDTokenJWSAlg(JWSAlgorithm.PS256);
        assertThat(meta.getIDTokenJWSAlg()).isEqualTo(JWSAlgorithm.PS256);

        assertThat(meta.getIDTokenJWEAlg()).isNull();
        meta.setIDTokenJWEAlg(JWEAlgorithm.A128KW);
        assertThat(meta.getIDTokenJWEAlg()).isEqualTo(JWEAlgorithm.A128KW);

        assertThat(meta.getIDTokenJWEEnc()).isNull();
        meta.setIDTokenJWEEnc(EncryptionMethod.A128GCM);
        assertThat(meta.getIDTokenJWEEnc()).isEqualTo(EncryptionMethod.A128GCM);

        assertThat(meta.getUserInfoJWSAlg()).isNull();
        meta.setUserInfoJWSAlg(JWSAlgorithm.ES256);
        assertThat(meta.getUserInfoJWSAlg()).isEqualTo(JWSAlgorithm.ES256);

        assertThat(meta.getUserInfoJWEAlg()).isNull();
        meta.setUserInfoJWEAlg(JWEAlgorithm.ECDH_ES);
        assertThat(meta.getUserInfoJWEAlg()).isEqualTo(JWEAlgorithm.ECDH_ES);

        assertThat(meta.getUserInfoJWEEnc()).isNull();
        meta.setUserInfoJWEEnc(EncryptionMethod.A128CBC_HS256);
        assertThat(meta.getUserInfoJWEEnc()).isEqualTo(EncryptionMethod.A128CBC_HS256);

        assertThat(meta.getDefaultMaxAge()).isEqualTo(-1);
        meta.setDefaultMaxAge(3600);
        assertThat(meta.getDefaultMaxAge()).isEqualTo(3600);

        assertThat(meta.requiresAuthTime()).isFalse();
        meta.requiresAuthTime(true);
        assertThat(meta.requiresAuthTime()).isTrue();

        assertThat(meta.getDefaultACRs()).isNull();
        List<ACR> acrList = new LinkedList<>();
        acrList.add(new ACR("1"));
        meta.setDefaultACRs(acrList);
        assertThat(meta.getDefaultACRs().get(0).toString()).isEqualTo("1");

        assertThat(meta.getInitiateLoginURI()).isNull();
        meta.setInitiateLoginURI(new URI("http://do-login.com"));
        assertThat(meta.getInitiateLoginURI().toString()).isEqualTo("http://do-login.com");

        assertThat(meta.getPostLogoutRedirectionURIs()).isNull();
        Set<URI> logoutURIs = new HashSet<>();
        logoutURIs.add(new URI("http://post-logout.com"));
        meta.setPostLogoutRedirectionURIs(logoutURIs);
        assertThat(meta.getPostLogoutRedirectionURIs().iterator().next().toString()).isEqualTo("http://post-logout.com");

        assertThat(meta.getFrontChannelLogoutURI()).isNull();
        meta.setFrontChannelLogoutURI(URI.create("https://example.com/logout/front-channel"));
        assertThat(meta.getFrontChannelLogoutURI()).isEqualTo(URI.create("https://example.com/logout/front-channel"));

        assertThat(meta.requiresFrontChannelLogoutSession()).isFalse();
        meta.requiresFrontChannelLogoutSession(true);
        assertThat(meta.requiresFrontChannelLogoutSession()).isTrue();

        assertThat(meta.getBackChannelLogoutURI()).isNull();
        meta.setBackChannelLogoutURI(URI.create("https://example.com/logout/back-channel"));
        assertThat(meta.getBackChannelLogoutURI()).isEqualTo(URI.create("https://example.com/logout/back-channel"));

        assertThat(meta.requiresBackChannelLogoutSession()).isFalse();
        meta.requiresBackChannelLogoutSession(true);
        assertThat(meta.requiresBackChannelLogoutSession()).isTrue();

        String json = meta.toJSONObject().build().toString();

        meta = OIDCClientMetadata.parse(JSONObjectUtils.parse(json));

        assertThat(meta.getApplicationType()).isEqualTo(ApplicationType.NATIVE);

        assertThat(meta.getSubjectType()).isEqualTo(SubjectType.PAIRWISE);

        assertThat(meta.getSectorIDURI().toString()).isEqualTo(sectorIDURI.toString());

        assertThat(meta.getRequestObjectURIs().iterator().next().toString()).isEqualTo("http://client.com/reqobj");
        assertThat(meta.getRequestObjectURIs()).hasSize(1);

        assertThat(meta.getRequestObjectJWSAlg()).isEqualTo(JWSAlgorithm.HS512);
        assertThat(meta.getRequestObjectJWEAlg()).isEqualTo(JWEAlgorithm.A128KW);
        assertThat(meta.getRequestObjectJWEEnc()).isEqualTo(EncryptionMethod.A128GCM);

        assertThat(meta.getTokenEndpointAuthJWSAlg()).isEqualTo(JWSAlgorithm.HS384);
        assertThat(meta.getIDTokenJWSAlg()).isEqualTo(JWSAlgorithm.PS256);
        assertThat(meta.getIDTokenJWEAlg()).isEqualTo(JWEAlgorithm.A128KW);
        assertThat(meta.getIDTokenJWEEnc()).isEqualTo(EncryptionMethod.A128GCM);

        assertThat(meta.getUserInfoJWSAlg()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(meta.getUserInfoJWEAlg()).isEqualTo(JWEAlgorithm.ECDH_ES);
        assertThat(meta.getUserInfoJWEEnc()).isEqualTo(EncryptionMethod.A128CBC_HS256);

        assertThat(meta.getDefaultMaxAge()).isEqualTo(3600);

        assertThat(meta.requiresAuthTime()).isTrue();

        assertThat(meta.getDefaultACRs().get(0).toString()).isEqualTo("1");

        assertThat(meta.getInitiateLoginURI().toString()).isEqualTo("http://do-login.com");

        assertThat(meta.getPostLogoutRedirectionURIs().iterator().next().toString()).isEqualTo("http://post-logout.com");

        assertThat(meta.getFrontChannelLogoutURI()).isEqualTo(URI.create("https://example.com/logout/front-channel"));
        assertThat(meta.requiresFrontChannelLogoutSession()).isTrue();

        assertThat(meta.getBackChannelLogoutURI()).isEqualTo(URI.create("https://example.com/logout/back-channel"));
        assertThat(meta.requiresBackChannelLogoutSession()).isTrue();
    }

    @Test
    public void testCustomFields()
            throws Exception {

        OIDCClientMetadata meta = new OIDCClientMetadata();

        meta.setCustomField("x-data", "123");

        assertThat(meta.getCustomField("x-data")).isEqualTo("123");
        assertThat(meta.getCustomFields().getString("x-data")).isEqualTo("123");
        assertThat(meta.getCustomFields()).hasSize(1);

        String json = meta.toJSONObject().build().toString();

        meta = OIDCClientMetadata.parse(JSONObjectUtils.parse(json));

        assertThat(meta.getCustomField("x-data")).isEqualTo("123");
        assertThat(meta.getCustomFields().getString("x-data")).isEqualTo("123");
        assertThat(meta.getCustomFields()).hasSize(1);
    }

    @Test
    public void testApplyDefaults() {

        OIDCClientMetadata metadata = new OIDCClientMetadata();

        assertThat(metadata.getResponseTypes()).isNull();
        assertThat(metadata.getGrantTypes()).isNull();
        assertThat(metadata.getTokenEndpointAuthMethod()).isNull();
        assertThat(metadata.getIDTokenJWSAlg()).isNull();
        assertThat(metadata.getApplicationType()).isNull();

        metadata.applyDefaults();

        assertThat(metadata.getResponseTypes().contains(ResponseType.getDefault())).isTrue();
        assertThat(metadata.getResponseTypes().contains(new ResponseType(ResponseType.Value.CODE))).isTrue();
        assertThat(metadata.getResponseTypes()).hasSize(1);

        assertThat(metadata.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE)).isTrue();
        assertThat(metadata.getGrantTypes()).hasSize(1);

        assertThat(metadata.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        assertThat(metadata.getIDTokenJWSAlg()).isEqualTo(JWSAlgorithm.RS256);

        assertThat(metadata.getApplicationType()).isEqualTo(ApplicationType.WEB);
    }

    @Test
    public void testApplyDefaults_JARM_implicitJWEEnc()
            throws Exception {

        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setAuthorizationJWEAlg(JWEAlgorithm.ECDH_ES);

        metadata.applyDefaults();

        Set<ResponseType> rts = metadata.getResponseTypes();
        assertThat(rts.contains(ResponseType.parse("code"))).isTrue();

        Set<GrantType> grantTypes = metadata.getGrantTypes();
        assertThat(grantTypes.contains(GrantType.AUTHORIZATION_CODE)).isTrue();

        assertThat(metadata.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        // JARM
        assertThat(metadata.getAuthorizationJWSAlg()).isNull();
        assertThat(metadata.getAuthorizationJWEAlg()).isEqualTo(JWEAlgorithm.ECDH_ES);
        assertThat(metadata.getAuthorizationJWEEnc()).isEqualTo(EncryptionMethod.A128CBC_HS256);
    }

    @Test
    public void testSerialiseDefaultRequireAuthTime() {

        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.applyDefaults();

        JsonObject jsonObject = metadata.toJSONObject().build();

        assertThat(jsonObject.get("require_auth_time")).isNull();
    }

    @Test
    public void testSerialiseNonDefaultRequireAuthTime() {

        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.requiresAuthTime(true);
        metadata.applyDefaults();

        JsonObject jsonObject = metadata.toJSONObject().build();

        assertThat(jsonObject.getBoolean("require_auth_time")).isTrue();
    }

    @Test
    public void testJOSEAlgEquality()
            throws Exception {

        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.applyDefaults();

        metadata.setIDTokenJWSAlg(JWSAlgorithm.RS256);
        metadata.setIDTokenJWEAlg(JWEAlgorithm.RSA_OAEP_256);
        metadata.setIDTokenJWEEnc(EncryptionMethod.A128GCM);

        metadata.setUserInfoJWSAlg(JWSAlgorithm.RS256);
        metadata.setUserInfoJWEAlg(JWEAlgorithm.RSA_OAEP_256);
        metadata.setUserInfoJWEEnc(EncryptionMethod.A128GCM);

        metadata.setRequestObjectJWSAlg(JWSAlgorithm.HS256);
        metadata.setRequestObjectJWEAlg(JWEAlgorithm.RSA_OAEP_256);
        metadata.setRequestObjectJWEEnc(EncryptionMethod.A128CBC_HS256);

        metadata = OIDCClientMetadata.parse(JSONObjectUtils.parse(metadata.toJSONObject().build().toString()));

        assertThat(metadata.getIDTokenJWSAlg()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(metadata.getIDTokenJWEAlg()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(metadata.getIDTokenJWEEnc()).isEqualTo(EncryptionMethod.A128GCM);

        assertThat(metadata.getUserInfoJWSAlg()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(metadata.getUserInfoJWEAlg()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(metadata.getIDTokenJWEEnc()).isEqualTo(EncryptionMethod.A128GCM);

        assertThat(metadata.getRequestObjectJWSAlg()).isEqualTo(JWSAlgorithm.HS256);
        assertThat(metadata.getRequestObjectJWEAlg()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(metadata.getRequestObjectJWEEnc()).isEqualTo(EncryptionMethod.A128CBC_HS256);
    }

    @Test
    public void testJOSEEncMethodParseWithCEKCheck()
            throws Exception {

        // See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issue/127/oidcclient-parse-method-causes-potential

        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.applyDefaults();

        metadata.setIDTokenJWEEnc(EncryptionMethod.A128GCM);
        metadata.setUserInfoJWEEnc(EncryptionMethod.A128GCM);
        metadata.setRequestObjectJWEEnc(EncryptionMethod.A128CBC_HS256);

        metadata = OIDCClientMetadata.parse(JSONObjectUtils.parse(metadata.toJSONObject().build().toString()));

        assertThat(metadata.getIDTokenJWEEnc().cekBitLength()).isEqualTo(128);
        assertThat(metadata.getUserInfoJWEEnc().cekBitLength()).isEqualTo(128);
        assertThat(metadata.getRequestObjectJWEEnc().cekBitLength()).isEqualTo(256);
    }

    @Test
    public void testClientAuthNoneWithImplicitGrant() {

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setGrantTypes(Collections.singleton(GrantType.IMPLICIT));
        clientMetadata.setResponseTypes(Collections.singleton(new ResponseType("token")));

        clientMetadata.applyDefaults();

        assertThat(clientMetadata.getGrantTypes()).isEqualTo(Collections.singleton(GrantType.IMPLICIT));
        assertThat(clientMetadata.getResponseTypes()).isEqualTo(Collections.singleton(new ResponseType("token")));
        assertThat(clientMetadata.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
    }

    @Test
    public void testInvalidClientMetadataErrorCode() {

        JsonObjectBuilder obuilder = Json.createObjectBuilder();
        obuilder.add("application_type", "xyz");

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                OIDCClientMetadata.parse(obuilder.build()));

        assertThat(exception.getMessage()).isEqualTo("Unexpected value of JSON object member with key \"application_type\"");
        assertThat(exception.getErrorObject().getCode()).isEqualTo(RegistrationError.INVALID_CLIENT_METADATA.getCode());
        assertThat(exception.getErrorObject().getDescription()).isEqualTo("Invalid client metadata field: Unexpected value of JSON object member with key \"application_type\"");

    }

    @Test
    public void testSectorIdentifierURICheck() {

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
                clientMetadata.setSectorIDURI(URI.create("http://example.com/callbacks.json")));

        assertThat(exception.getMessage()).isEqualTo("The URI must have a https scheme");


        exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
                clientMetadata.setSectorIDURI(URI.create("https:///callbacks.json")));

        assertThat(exception.getMessage()).isEqualTo("The URI must contain a host component");

    }

    @Test
    public void testResolveSectorIdentifier_simpleCase() {

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setSubjectType(SubjectType.PAIRWISE);
        clientMetadata.setRedirectionURI(URI.create("https://example.com/callback"));
        assertThat(clientMetadata.resolveSectorID()).isEqualTo(new SectorID("example.com"));
    }

    @Test
    public void testResolveSectorIdentifier_fromSectorIDURI_opt() {

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setSubjectType(SubjectType.PAIRWISE);
        clientMetadata.setRedirectionURI(URI.create("https://myapp.com/callback"));
        clientMetadata.setSectorIDURI(URI.create("https://example.com/apps.json"));
        assertThat(clientMetadata.resolveSectorID()).isEqualTo(new SectorID("example.com"));
    }

    @Test
    public void testResolveSectorIdentifier_fromSectorIDURI_required() {

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setSubjectType(SubjectType.PAIRWISE);
        clientMetadata.setRedirectionURIs(new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback"))));
        clientMetadata.setSectorIDURI(URI.create("https://example.com/apps.json"));
        assertThat(clientMetadata.resolveSectorID()).isEqualTo(new SectorID("example.com"));
    }

    @Test
    public void testResolveSectorIdentifier_missingSectorIDURIError() {

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setSubjectType(SubjectType.PAIRWISE);
        clientMetadata.setRedirectionURIs(new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback"))));
        try {
            clientMetadata.resolveSectorID();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo("Couldn't resolve sector ID: More than one redirect_uri, sector_identifier_uri not specified");
        }
    }

    @Test
    public void testResolveSectorIdentifier_missingRedirectURIError() {

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setSubjectType(SubjectType.PAIRWISE);
        try {
            clientMetadata.resolveSectorID();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo("Couldn't resolve sector ID: Missing redirect_uris");
        }
    }

    @Test
    public void testResolveSectorIdentifier_publicSubjectType() {

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setSubjectType(SubjectType.PUBLIC);
        assertThat(clientMetadata.resolveSectorID()).isNull();
    }

    @Test
    public void testResolveSectorIdentifier_nullSubjectType() {

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setSubjectType(null);
        assertThat(clientMetadata.resolveSectorID()).isNull();
    }

    @Test
    public void testOverrideToJSONObjectWithCustomFields() {

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
        clientMetadata.setSubjectType(SubjectType.PAIRWISE);
        clientMetadata.setSectorIDURI(URI.create("https://example.com/sector.json"));
        clientMetadata.applyDefaults();

        JsonObject jsonObject = clientMetadata.toJSONObject(true).build();
        assertThat(jsonObject.get("grant_types")).isNotNull();
        assertThat(jsonObject.get("response_types")).isNotNull();
        assertThat(jsonObject.get("redirect_uris")).isNotNull();
        assertThat(jsonObject.get("token_endpoint_auth_method")).isNotNull();
        assertThat(jsonObject.get("application_type")).isNotNull();
        assertThat(jsonObject.get("subject_type")).isNotNull();
        assertThat(jsonObject.get("sector_identifier_uri")).isNotNull();
        assertThat(jsonObject.get("id_token_signed_response_alg")).isNotNull();
        assertThat(jsonObject.getBoolean("tls_client_certificate_bound_access_tokens")).isFalse();

        assertThat(jsonObject).hasSize(9);
    }

    @Test
    public void testPermitParseNullValues()
            throws Exception {

        JsonObjectBuilder jsonObjectbuilder = Json.createObjectBuilder();

        for (String paramName : OIDCClientMetadata.getRegisteredParameterNames()) {

            jsonObjectbuilder.addNull(paramName);
        }

        OIDCClientMetadata.parse(jsonObjectbuilder.build());
    }

    @Test
    public void testJSONObjectFrontChannelLogoutParams()
            throws OAuth2JSONParseException {

        URI logoutURI = URI.create("https://example.com/logout/front-channel");

        // default
        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.applyDefaults();
        JsonObject out = clientMetadata.toJSONObject().build();
        assertThat(out.get("frontchannel_logout_uri")).isNull();
        assertThat(out.get("frontchannel_logout_session_required")).isNull();

        // with logout URI
        clientMetadata.setFrontChannelLogoutURI(logoutURI);
        out = clientMetadata.toJSONObject().build();
        assertThat(out.getString("frontchannel_logout_uri")).isEqualTo(logoutURI.toString());
        assertThat(out.getBoolean("frontchannel_logout_session_required")).isFalse();

        clientMetadata = OIDCClientMetadata.parse(out);
        assertThat(clientMetadata.getFrontChannelLogoutURI()).isEqualTo(logoutURI);
        assertThat(clientMetadata.requiresFrontChannelLogoutSession()).isFalse();

        // with logout URI and SID requirement
        clientMetadata.requiresFrontChannelLogoutSession(true);
        out = clientMetadata.toJSONObject().build();
        assertThat(out.getString("frontchannel_logout_uri")).isEqualTo(logoutURI.toString());
        assertThat(out.getBoolean("frontchannel_logout_session_required")).isTrue();

        clientMetadata = OIDCClientMetadata.parse(out);
        assertThat(clientMetadata.getFrontChannelLogoutURI()).isEqualTo(logoutURI);
        assertThat(clientMetadata.requiresFrontChannelLogoutSession()).isTrue();

        // with logout URI and SID requirement defaulting to false
        clientMetadata.requiresFrontChannelLogoutSession(false);
        out = clientMetadata.toJSONObject().build();
        assertThat(out.getString("frontchannel_logout_uri")).isEqualTo(logoutURI.toString());
        assertThat(out.containsKey("frontchannel_logout_session_required")).isTrue();

        out = JSONObjectUtils.remove(out, "frontchannel_logout_session_required");

        clientMetadata = OIDCClientMetadata.parse(out);
        assertThat(clientMetadata.getFrontChannelLogoutURI()).isEqualTo(logoutURI);
        assertThat(clientMetadata.requiresFrontChannelLogoutSession()).isFalse();
    }

    @Test
    public void testJSONObjectBackChannelLogoutParams()
            throws OAuth2JSONParseException {

        URI logoutURI = URI.create("https://example.com/logout/back-channel");

        // default
        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.applyDefaults();
        JsonObject out = clientMetadata.toJSONObject().build();
        assertThat(out.get("backchannel_logout_uri")).isNull();
        assertThat(out.get("backchannel_logout_session_required")).isNull();

        // with logout URI
        clientMetadata.setBackChannelLogoutURI(logoutURI);
        out = clientMetadata.toJSONObject().build();
        assertThat(out.getString("backchannel_logout_uri")).isEqualTo(logoutURI.toString());
        assertThat(out.getBoolean("backchannel_logout_session_required")).isFalse();

        clientMetadata = OIDCClientMetadata.parse(out);
        assertThat(clientMetadata.getBackChannelLogoutURI()).isEqualTo(logoutURI);
        assertThat(clientMetadata.requiresBackChannelLogoutSession()).isFalse();

        // with logout URI and SID requirement
        clientMetadata.requiresBackChannelLogoutSession(true);
        out = clientMetadata.toJSONObject().build();
        assertThat(out.getString("backchannel_logout_uri")).isEqualTo(logoutURI.toString());
        assertThat(out.getBoolean("backchannel_logout_session_required")).isTrue();

        clientMetadata = OIDCClientMetadata.parse(out);
        assertThat(clientMetadata.getBackChannelLogoutURI()).isEqualTo(logoutURI);
        assertThat(clientMetadata.requiresBackChannelLogoutSession()).isTrue();

        // with logout URI and SID requirement defaulting to false
        clientMetadata.requiresBackChannelLogoutSession(false);
        out = clientMetadata.toJSONObject().build();
        assertThat(out.getString("backchannel_logout_uri")).isEqualTo(logoutURI.toString());
        assertThat(out.containsKey("backchannel_logout_session_required")).isTrue();

        out = JSONObjectUtils.remove(out, "backchannel_logout_session_required");

        clientMetadata = OIDCClientMetadata.parse(out);
        assertThat(clientMetadata.getBackChannelLogoutURI()).isEqualTo(logoutURI);
        assertThat(clientMetadata.requiresBackChannelLogoutSession()).isFalse();
    }

    @Test
    public void testJARM()
            throws OAuth2JSONParseException {

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();

        assertThat(clientMetadata.getAuthorizationJWSAlg()).isNull();
        assertThat(clientMetadata.getAuthorizationJWEAlg()).isNull();
        assertThat(clientMetadata.getAuthorizationJWEEnc()).isNull();

        clientMetadata.setAuthorizationJWSAlg(JWSAlgorithm.ES256);
        assertThat(clientMetadata.getAuthorizationJWSAlg()).isEqualTo(JWSAlgorithm.ES256);

        clientMetadata.setAuthorizationJWEAlg(JWEAlgorithm.ECDH_ES);
        assertThat(clientMetadata.getAuthorizationJWEAlg()).isEqualTo(JWEAlgorithm.ECDH_ES);

        clientMetadata.setAuthorizationJWEEnc(EncryptionMethod.A256GCM);
        assertThat(clientMetadata.getAuthorizationJWEEnc()).isEqualTo(EncryptionMethod.A256GCM);

        JsonObject jsonObject = clientMetadata.toJSONObject().build();

        assertThat(jsonObject.getString("authorization_signed_response_alg")).isEqualTo(JWSAlgorithm.ES256.getName());
        assertThat(jsonObject.getString("authorization_encrypted_response_alg")).isEqualTo(JWEAlgorithm.ECDH_ES.getName());
        assertThat(jsonObject.getString("authorization_encrypted_response_enc")).isEqualTo(EncryptionMethod.A256GCM.getName());

        clientMetadata = OIDCClientMetadata.parse(jsonObject);

        assertThat(clientMetadata.getAuthorizationJWSAlg()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(clientMetadata.getAuthorizationJWEAlg()).isEqualTo(JWEAlgorithm.ECDH_ES);
        assertThat(clientMetadata.getAuthorizationJWEEnc()).isEqualTo(EncryptionMethod.A256GCM);
    }
}