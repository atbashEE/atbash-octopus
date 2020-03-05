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
package be.atbash.ee.oauth2.sdk.client;


import be.atbash.ee.oauth2.sdk.GrantType;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.ResponseType;
import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.id.SoftwareID;
import be.atbash.ee.oauth2.sdk.id.SoftwareVersion;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.mail.internet.InternetAddress;
import java.net.URI;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the OAuth 2.0 client metadata class.
 */
public class ClientMetadataTest {

    @Test
    public void testRegisteredParameters() {

        Set<String> paramNames = ClientMetadata.getRegisteredParameterNames();

        assertThat(paramNames).contains("redirect_uris");
        assertThat(paramNames).contains("client_name");
        assertThat(paramNames).contains("client_uri");
        assertThat(paramNames).contains("logo_uri");
        assertThat(paramNames).contains("contacts");
        assertThat(paramNames).contains("tos_uri");
        assertThat(paramNames).contains("policy_uri");
        assertThat(paramNames).contains("token_endpoint_auth_method");
        assertThat(paramNames).contains("token_endpoint_auth_signing_alg");
        assertThat(paramNames).contains("scope");
        assertThat(paramNames).contains("grant_types");
        assertThat(paramNames).contains("response_types");
        assertThat(paramNames).contains("jwks_uri");
        assertThat(paramNames).contains("jwks");
        assertThat(paramNames).contains("request_uris");
        assertThat(paramNames).contains("request_object_signing_alg");
        assertThat(paramNames).contains("request_object_encryption_alg");
        assertThat(paramNames).contains("request_object_encryption_enc");
        assertThat(paramNames).contains("software_id");
        assertThat(paramNames).contains("software_version");
        assertThat(paramNames).contains("tls_client_certificate_bound_access_tokens");
        assertThat(paramNames).contains("tls_client_auth_subject_dn");
        assertThat(paramNames).contains("tls_client_auth_san_dns");
        assertThat(paramNames).contains("tls_client_auth_san_uri");
        assertThat(paramNames).contains("tls_client_auth_san_ip");
        assertThat(paramNames).contains("tls_client_auth_san_email");
        assertThat(paramNames).contains("authorization_signed_response_alg");
        assertThat(paramNames).contains("authorization_encrypted_response_enc");
        assertThat(paramNames).contains("authorization_encrypted_response_enc");

        assertThat(ClientMetadata.getRegisteredParameterNames()).hasSize(29);
    }

    @Test
    public void testSerializeAndParse()
            throws Exception {

        ClientMetadata meta = new ClientMetadata();

        Set<URI> redirectURIs = new HashSet<>();
        redirectURIs.add(new URI("http://example.com/1"));
        redirectURIs.add(new URI("http://example.com/2"));
        meta.setRedirectionURIs(redirectURIs);

        Scope scope = Scope.parse("read write");
        assertThat(meta.hasScopeValue(new Scope.Value("read"))).isFalse();
        meta.setScope(scope);
        assertThat(meta.hasScopeValue(new Scope.Value("read"))).isTrue();
        assertThat(meta.hasScopeValue(new Scope.Value("write"))).isTrue();

        Set<ResponseType> rts = new HashSet<>();
        rts.add(ResponseType.parse("code id_token"));
        meta.setResponseTypes(rts);

        Set<GrantType> grantTypes = new HashSet<>();
        grantTypes.add(GrantType.AUTHORIZATION_CODE);
        grantTypes.add(GrantType.REFRESH_TOKEN);
        meta.setGrantTypes(grantTypes);

        List<String> contacts = new LinkedList<>();
        contacts.add("alice@wonderland.net");
        contacts.add("admin@wonderland.net");
        meta.setEmailContacts(contacts);

        String name = "My Example App";
        meta.setName(name);

        URI logo = new URI("http://example.com/logo.png");
        meta.setLogoURI(logo);

        URI uri = new URI("http://example.com");
        meta.setURI(uri);

        URI policy = new URI("http://example.com/policy");
        meta.setPolicyURI(policy);

        URI tos = new URI("http://example.com/tos");
        meta.setTermsOfServiceURI(tos);

        ClientAuthenticationMethod authMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT;
        meta.setTokenEndpointAuthMethod(authMethod);

        JWSAlgorithm authJWSAlg = JWSAlgorithm.HS256;
        meta.setTokenEndpointAuthJWSAlg(authJWSAlg);

        URI jwksURI = new URI("http://example.com/jwks.json");
        meta.setJWKSetURI(jwksURI);

        RSAKey rsaKey = new RSAKey.Builder(new Base64URLValue("nabc"), new Base64URLValue("eabc")).build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        meta.setJWKSet(jwkSet);

        Set<URI> requestObjURIs = Collections.singleton(new URI("http://client.com/reqobj"));
        meta.setRequestObjectURIs(requestObjURIs);
        meta.setRequestObjectJWSAlg(JWSAlgorithm.HS512);
        meta.setRequestObjectJWEAlg(JWEAlgorithm.A128KW);
        meta.setRequestObjectJWEEnc(EncryptionMethod.A128GCM);

        SoftwareID softwareID = new SoftwareID();
        meta.setSoftwareID(softwareID);

        SoftwareVersion softwareVersion = new SoftwareVersion("1.0");
        meta.setSoftwareVersion(softwareVersion);

        assertThat(meta.getTLSClientCertificateBoundAccessTokens()).isFalse();
        assertThat(meta.getMutualTLSSenderConstrainedAccessTokens()).isFalse();
        meta.setTLSClientCertificateBoundAccessTokens(true);

        assertThat(meta.getTLSClientAuthSubjectDN()).isNull();
        String subjectDN = "cn=123";
        meta.setTLSClientAuthSubjectDN(subjectDN);

        assertThat(meta.getTLSClientAuthSanDNS()).isNull();
        String sanDNS = "example.com";
        meta.setTLSClientAuthSanDNS(sanDNS);

        assertThat(meta.getTLSClientAuthSanURI()).isNull();
        String sanURI = "http://example.com/";
        meta.setTLSClientAuthSanURI(sanURI);

        assertThat(meta.getTLSClientAuthSanIP()).isNull();
        String sanIP = "1.2.3.4";
        meta.setTLSClientAuthSanIP(sanIP);

        assertThat(meta.getTLSClientAuthSanEmail()).isNull();
        String sanEmail = "me@example.com";
        meta.setTLSClientAuthSanEmail(sanEmail);


        JWSAlgorithm authzJWSAlg = JWSAlgorithm.ES512;
        meta.setAuthorizationJWSAlg(authzJWSAlg);
        assertThat(meta.getAuthorizationJWSAlg()).isEqualTo(authzJWSAlg);

        JWEAlgorithm authzJWEAlg = JWEAlgorithm.ECDH_ES_A256KW;
        meta.setAuthorizationJWEAlg(authzJWEAlg);
        assertThat(meta.getAuthorizationJWEAlg()).isEqualTo(authzJWEAlg);

        EncryptionMethod authzJWEEnc = EncryptionMethod.A256GCM;
        meta.setAuthorizationJWEEnc(authzJWEEnc);
        assertThat(meta.getAuthorizationJWEEnc()).isEqualTo(authzJWEEnc);

        // Test getters
        assertThat(meta.getRedirectionURIs()).isEqualTo(redirectURIs);
        assertThat(meta.getScope()).isEqualTo(scope);
        assertThat(meta.getGrantTypes()).isEqualTo(grantTypes);
        assertThat(meta.getEmailContacts()).isEqualTo(contacts);
        assertThat(meta.getName()).isEqualTo(name);
        assertThat(meta.getLogoURI()).isEqualTo(logo);
        assertThat(meta.getURI()).isEqualTo(uri);
        assertThat(meta.getPolicyURI()).isEqualTo(policy);
        assertThat(meta.getTermsOfServiceURI()).isEqualTo(tos);
        assertThat(meta.getTokenEndpointAuthMethod()).isEqualTo(authMethod);
        assertThat(meta.getTokenEndpointAuthJWSAlg()).isEqualTo(authJWSAlg);
        assertThat(meta.getJWKSetURI()).isEqualTo(jwksURI);
        assertThat(((RSAKey) meta.getJWKSet().getKeys().get(0)).getModulus().toString()).isEqualTo("nabc");
        assertThat(((RSAKey) meta.getJWKSet().getKeys().get(0)).getPublicExponent().toString()).isEqualTo("eabc");
        assertThat(meta.getRequestObjectURIs()).isEqualTo(requestObjURIs);
        assertThat(meta.getRequestObjectJWSAlg()).isEqualTo(JWSAlgorithm.HS512);
        assertThat(meta.getRequestObjectJWEAlg()).isEqualTo(JWEAlgorithm.A128KW);
        assertThat(meta.getRequestObjectJWEEnc()).isEqualTo(EncryptionMethod.A128GCM);
        assertThat(meta.getJWKSet().getKeys()).hasSize(1);
        assertThat(meta.getSoftwareID()).isEqualTo(softwareID);
        assertThat(meta.getSoftwareVersion()).isEqualTo(softwareVersion);
        assertThat(meta.getTLSClientCertificateBoundAccessTokens()).isTrue();
        assertThat(meta.getMutualTLSSenderConstrainedAccessTokens()).isTrue();
        assertThat(meta.getTLSClientAuthSubjectDN()).isEqualTo(subjectDN);
        assertThat(meta.getTLSClientAuthSanDNS()).isEqualTo(sanDNS);
        assertThat(meta.getTLSClientAuthSanURI()).isEqualTo(sanURI);
        assertThat(meta.getTLSClientAuthSanIP()).isEqualTo(sanIP);
        assertThat(meta.getTLSClientAuthSanEmail()).isEqualTo(sanEmail);
        assertThat(meta.getAuthorizationJWSAlg()).isEqualTo(authzJWSAlg);
        assertThat(meta.getAuthorizationJWEAlg()).isEqualTo(authzJWEAlg);
        assertThat(meta.getAuthorizationJWEEnc()).isEqualTo(authzJWEEnc);
        assertThat(meta.getCustomFields().isEmpty()).isTrue();

        String json = meta.toJSONObject().build().toString();

        JsonObject jsonObject = JSONObjectUtils.parse(json);

        meta = ClientMetadata.parse(jsonObject);

        // Test getters
        assertThat(meta.getRedirectionURIs()).isEqualTo(redirectURIs);
        assertThat(meta.getScope()).isEqualTo(scope);
        assertThat(meta.hasScopeValue(new Scope.Value("read"))).isTrue();
        assertThat(meta.hasScopeValue(new Scope.Value("write"))).isTrue();
        assertThat(meta.getGrantTypes()).isEqualTo(grantTypes);
        assertThat(meta.getEmailContacts()).isEqualTo(contacts);
        assertThat(meta.getName()).isEqualTo(name);
        assertThat(meta.getLogoURI()).isEqualTo(logo);
        assertThat(meta.getURI()).isEqualTo(uri);
        assertThat(meta.getPolicyURI()).isEqualTo(policy);
        assertThat(meta.getTermsOfServiceURI()).isEqualTo(tos);
        assertThat(meta.getTokenEndpointAuthMethod()).isEqualTo(authMethod);
        assertThat(meta.getTokenEndpointAuthJWSAlg()).isEqualTo(authJWSAlg);
        assertThat(meta.getJWKSetURI()).isEqualTo(jwksURI);
        assertThat(((RSAKey) meta.getJWKSet().getKeys().get(0)).getModulus().toString()).isEqualTo("nabc");
        assertThat(((RSAKey) meta.getJWKSet().getKeys().get(0)).getPublicExponent().toString()).isEqualTo("eabc");
        assertThat(meta.getJWKSet().getKeys()).hasSize(1);
        assertThat(meta.getRequestObjectURIs()).isEqualTo(requestObjURIs);
        assertThat(meta.getRequestObjectJWSAlg()).isEqualTo(JWSAlgorithm.HS512);
        assertThat(meta.getRequestObjectJWEAlg()).isEqualTo(JWEAlgorithm.A128KW);
        assertThat(meta.getRequestObjectJWEEnc()).isEqualTo(EncryptionMethod.A128GCM);
        assertThat(meta.getSoftwareID()).isEqualTo(softwareID);
        assertThat(meta.getSoftwareVersion()).isEqualTo(softwareVersion);
        assertThat(meta.getTLSClientCertificateBoundAccessTokens()).isTrue();
        assertThat(meta.getMutualTLSSenderConstrainedAccessTokens()).isTrue();
        assertThat(meta.getTLSClientAuthSubjectDN()).isEqualTo(subjectDN);
        assertThat(meta.getAuthorizationJWSAlg()).isEqualTo(authzJWSAlg);
        assertThat(meta.getAuthorizationJWEAlg()).isEqualTo(authzJWEAlg);
        assertThat(meta.getAuthorizationJWEEnc()).isEqualTo(authzJWEEnc);

        assertThat(meta.getCustomFields().isEmpty()).isTrue();
    }

    @Test
    public void testSerializeAndParse_deprecatedInternetAddressContacts()
            throws Exception {

        ClientMetadata meta = new ClientMetadata();

        Set<URI> redirectURIs = new HashSet<>();
        redirectURIs.add(new URI("http://example.com/1"));
        redirectURIs.add(new URI("http://example.com/2"));
        meta.setRedirectionURIs(redirectURIs);

        Scope scope = Scope.parse("read write");
        assertThat(meta.hasScopeValue(new Scope.Value("read"))).isFalse();
        meta.setScope(scope);
        assertThat(meta.hasScopeValue(new Scope.Value("read"))).isTrue();
        assertThat(meta.hasScopeValue(new Scope.Value("write"))).isTrue();

        Set<ResponseType> rts = new HashSet<>();
        rts.add(ResponseType.parse("code id_token"));
        meta.setResponseTypes(rts);

        Set<GrantType> grantTypes = new HashSet<>();
        grantTypes.add(GrantType.AUTHORIZATION_CODE);
        grantTypes.add(GrantType.REFRESH_TOKEN);
        meta.setGrantTypes(grantTypes);

        List<InternetAddress> contacts = new LinkedList<>();
        contacts.add(new InternetAddress("alice@wonderland.net"));
        contacts.add(new InternetAddress("admin@wonderland.net"));
        meta.setContacts(contacts);

        String name = "My Example App";
        meta.setName(name);

        URI logo = new URI("http://example.com/logo.png");
        meta.setLogoURI(logo);

        URI uri = new URI("http://example.com");
        meta.setURI(uri);

        URI policy = new URI("http://example.com/policy");
        meta.setPolicyURI(policy);

        URI tos = new URI("http://example.com/tos");
        meta.setTermsOfServiceURI(tos);

        ClientAuthenticationMethod authMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT;
        meta.setTokenEndpointAuthMethod(authMethod);

        JWSAlgorithm authJWSAlg = JWSAlgorithm.HS256;
        meta.setTokenEndpointAuthJWSAlg(authJWSAlg);

        URI jwksURI = new URI("http://example.com/jwks.json");
        meta.setJWKSetURI(jwksURI);

        RSAKey rsaKey = new RSAKey.Builder(new Base64URLValue("nabc"), new Base64URLValue("eabc")).build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        meta.setJWKSet(jwkSet);

        SoftwareID softwareID = new SoftwareID();
        meta.setSoftwareID(softwareID);

        SoftwareVersion softwareVersion = new SoftwareVersion("1.0");
        meta.setSoftwareVersion(softwareVersion);

        // Test getters
        assertThat(meta.getRedirectionURIs()).isEqualTo(redirectURIs);
        assertThat(meta.getScope()).isEqualTo(scope);
        assertThat(meta.getGrantTypes()).isEqualTo(grantTypes);
        assertThat(meta.getContacts()).isEqualTo(contacts);
        assertThat(meta.getName()).isEqualTo(name);
        assertThat(meta.getLogoURI()).isEqualTo(logo);
        assertThat(meta.getURI()).isEqualTo(uri);
        assertThat(meta.getPolicyURI()).isEqualTo(policy);
        assertThat(meta.getTermsOfServiceURI()).isEqualTo(tos);
        assertThat(meta.getTokenEndpointAuthMethod()).isEqualTo(authMethod);
        assertThat(meta.getTokenEndpointAuthJWSAlg()).isEqualTo(authJWSAlg);
        assertThat(meta.getJWKSetURI()).isEqualTo(jwksURI);
        assertThat(((RSAKey) meta.getJWKSet().getKeys().get(0)).getModulus().toString()).isEqualTo("nabc");
        assertThat(((RSAKey) meta.getJWKSet().getKeys().get(0)).getPublicExponent().toString()).isEqualTo("eabc");
        assertThat(meta.getJWKSet().getKeys()).hasSize(1);
        assertThat(meta.getSoftwareID()).isEqualTo(softwareID);
        assertThat(meta.getSoftwareVersion()).isEqualTo(softwareVersion);
        assertThat(meta.getCustomFields().isEmpty()).isTrue();

        String json = meta.toJSONObject().build().toString();

        JsonObject jsonObject = JSONObjectUtils.parse(json);

        meta = ClientMetadata.parse(jsonObject);

        // Test getters
        assertThat(meta.getRedirectionURIs()).isEqualTo(redirectURIs);
        assertThat(meta.getScope()).isEqualTo(scope);
        assertThat(meta.hasScopeValue(new Scope.Value("read"))).isTrue();
        assertThat(meta.hasScopeValue(new Scope.Value("write"))).isTrue();
        assertThat(meta.getGrantTypes()).isEqualTo(grantTypes);
        assertThat(meta.getContacts()).isEqualTo(contacts);
        assertThat(meta.getName()).isEqualTo(name);
        assertThat(meta.getLogoURI()).isEqualTo(logo);
        assertThat(meta.getURI()).isEqualTo(uri);
        assertThat(meta.getPolicyURI()).isEqualTo(policy);
        assertThat(meta.getTermsOfServiceURI()).isEqualTo(tos);
        assertThat(meta.getTokenEndpointAuthMethod()).isEqualTo(authMethod);
        assertThat(meta.getTokenEndpointAuthJWSAlg()).isEqualTo(authJWSAlg);
        assertThat(meta.getJWKSetURI()).isEqualTo(jwksURI);
        assertThat(((RSAKey) meta.getJWKSet().getKeys().get(0)).getModulus().toString()).isEqualTo("nabc");
        assertThat(((RSAKey) meta.getJWKSet().getKeys().get(0)).getPublicExponent().toString()).isEqualTo("eabc");
        assertThat(meta.getJWKSet().getKeys()).hasSize(1);
        assertThat(meta.getSoftwareID()).isEqualTo(softwareID);
        assertThat(meta.getSoftwareVersion()).isEqualTo(softwareVersion);

        assertThat(meta.getCustomFields().isEmpty()).isTrue();
    }

    @Test
    public void testCopyConstructor()
            throws Exception {

        ClientMetadata meta = new ClientMetadata();

        Set<URI> redirectURIs = new HashSet<>();
        redirectURIs.add(new URI("http://example.com/1"));
        redirectURIs.add(new URI("http://example.com/2"));
        meta.setRedirectionURIs(redirectURIs);

        Scope scope = Scope.parse("read write");
        meta.setScope(scope);

        Set<ResponseType> rts = new HashSet<>();
        rts.add(ResponseType.parse("code id_token"));
        meta.setResponseTypes(rts);

        Set<GrantType> grantTypes = new HashSet<>();
        grantTypes.add(GrantType.AUTHORIZATION_CODE);
        grantTypes.add(GrantType.REFRESH_TOKEN);
        meta.setGrantTypes(grantTypes);

        List<String> contacts = new LinkedList<>();
        contacts.add("alice@wonderland.net");
        contacts.add("admin@wonderland.net");
        meta.setEmailContacts(contacts);

        String name = "My Example App";
        meta.setName(name);

        URI logo = new URI("http://example.com/logo.png");
        meta.setLogoURI(logo);

        URI uri = new URI("http://example.com");
        meta.setURI(uri);

        URI policy = new URI("http://example.com/policy");
        meta.setPolicyURI(policy);

        URI tos = new URI("http://example.com/tos");
        meta.setTermsOfServiceURI(tos);

        ClientAuthenticationMethod authMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT;
        meta.setTokenEndpointAuthMethod(authMethod);

        JWSAlgorithm authJWSAlg = JWSAlgorithm.HS256;
        meta.setTokenEndpointAuthJWSAlg(authJWSAlg);

        URI jwksURI = new URI("http://example.com/jwks.json");
        meta.setJWKSetURI(jwksURI);

        RSAKey rsaKey = new RSAKey.Builder(new Base64URLValue("nabc"), new Base64URLValue("eabc")).build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        meta.setJWKSet(jwkSet);

        Set<URI> requestObjURIs = Collections.singleton(new URI("http://client.com/reqobj"));
        meta.setRequestObjectURIs(requestObjURIs);
        meta.setRequestObjectJWSAlg(JWSAlgorithm.HS512);
        meta.setRequestObjectJWEAlg(JWEAlgorithm.A128KW);
        meta.setRequestObjectJWEEnc(EncryptionMethod.A128GCM);

        SoftwareID softwareID = new SoftwareID();
        meta.setSoftwareID(softwareID);

        SoftwareVersion softwareVersion = new SoftwareVersion("1.0");
        meta.setSoftwareVersion(softwareVersion);

        meta.setTLSClientCertificateBoundAccessTokens(true);

        String subjectDN = "cn=123";
        meta.setTLSClientAuthSubjectDN(subjectDN);

        String sanDNS = "example.com";
        meta.setTLSClientAuthSanDNS(sanDNS);

        String sanURI = "http://example.com/";
        meta.setTLSClientAuthSanURI(sanURI);

        String sanIP = "1.2.3.4";
        meta.setTLSClientAuthSanIP(sanIP);

        String sanEmail = "me@example.com";
        meta.setTLSClientAuthSanEmail(sanEmail);

        JWSAlgorithm authzJWSAlg = JWSAlgorithm.ES512;
        meta.setAuthorizationJWSAlg(authzJWSAlg);

        JWEAlgorithm authzJWEAlg = JWEAlgorithm.ECDH_ES_A256KW;
        meta.setAuthorizationJWEAlg(authzJWEAlg);

        EncryptionMethod authzJWEEnc = EncryptionMethod.A256GCM;
        meta.setAuthorizationJWEEnc(authzJWEEnc);

        // Shallow copy
        ClientMetadata copy = new ClientMetadata(meta);

        // Test getters
        assertThat(copy.getRedirectionURIs()).isEqualTo(redirectURIs);
        assertThat(copy.getScope()).isEqualTo(scope);
        assertThat(copy.getGrantTypes()).isEqualTo(grantTypes);
        assertThat(copy.getEmailContacts()).isEqualTo(contacts);
        assertThat(copy.getName()).isEqualTo(name);
        assertThat(copy.getLogoURI()).isEqualTo(logo);
        assertThat(copy.getURI()).isEqualTo(uri);
        assertThat(copy.getPolicyURI()).isEqualTo(policy);
        assertThat(copy.getTermsOfServiceURI()).isEqualTo(tos);
        assertThat(copy.getTokenEndpointAuthMethod()).isEqualTo(authMethod);
        assertThat(copy.getTokenEndpointAuthJWSAlg()).isEqualTo(authJWSAlg);
        assertThat(copy.getJWKSetURI()).isEqualTo(jwksURI);
        assertThat(((RSAKey) copy.getJWKSet().getKeys().get(0)).getModulus().toString()).isEqualTo("nabc");
        assertThat(((RSAKey) copy.getJWKSet().getKeys().get(0)).getPublicExponent().toString()).isEqualTo("eabc");
        assertThat(copy.getJWKSet().getKeys()).hasSize(1);
        assertThat(meta.getRequestObjectURIs()).isEqualTo(requestObjURIs);
        assertThat(meta.getRequestObjectJWSAlg()).isEqualTo(JWSAlgorithm.HS512);
        assertThat(meta.getRequestObjectJWEAlg()).isEqualTo(JWEAlgorithm.A128KW);
        assertThat(meta.getRequestObjectJWEEnc()).isEqualTo(EncryptionMethod.A128GCM);
        assertThat(copy.getSoftwareID()).isEqualTo(softwareID);
        assertThat(copy.getSoftwareVersion()).isEqualTo(softwareVersion);
        assertThat(copy.getTLSClientCertificateBoundAccessTokens()).isTrue();
        assertThat(copy.getMutualTLSSenderConstrainedAccessTokens()).isTrue();
        assertThat(copy.getTLSClientAuthSubjectDN()).isEqualTo(subjectDN);
        assertThat(copy.getTLSClientAuthSanDNS()).isEqualTo(sanDNS);
        assertThat(copy.getTLSClientAuthSanURI()).isEqualTo(sanURI);
        assertThat(copy.getTLSClientAuthSanIP()).isEqualTo(sanIP);
        assertThat(copy.getTLSClientAuthSanEmail()).isEqualTo(sanEmail);
        assertThat(copy.getCustomFields().isEmpty()).isTrue();
        assertThat(copy.getAuthorizationJWSAlg()).isEqualTo(authzJWSAlg);
        assertThat(copy.getAuthorizationJWEAlg()).isEqualTo(authzJWEAlg);
        assertThat(copy.getAuthorizationJWEEnc()).isEqualTo(authzJWEEnc);

        String json = copy.toJSONObject().build().toString();

        JsonObject jsonObject = JSONObjectUtils.parse(json);

        copy = ClientMetadata.parse(jsonObject);

        // Test getters
        assertThat(copy.getRedirectionURIs()).isEqualTo(redirectURIs);
        assertThat(copy.getScope()).isEqualTo(scope);
        assertThat(copy.getGrantTypes()).isEqualTo(grantTypes);
        assertThat(copy.getEmailContacts()).isEqualTo(contacts);
        assertThat(copy.getName()).isEqualTo(name);
        assertThat(copy.getLogoURI()).isEqualTo(logo);
        assertThat(copy.getURI()).isEqualTo(uri);
        assertThat(copy.getPolicyURI()).isEqualTo(policy);
        assertThat(copy.getTermsOfServiceURI()).isEqualTo(tos);
        assertThat(copy.getTokenEndpointAuthMethod()).isEqualTo(authMethod);
        assertThat(copy.getTokenEndpointAuthJWSAlg()).isEqualTo(authJWSAlg);
        assertThat(copy.getJWKSetURI()).isEqualTo(jwksURI);
        assertThat(((RSAKey) copy.getJWKSet().getKeys().get(0)).getModulus().toString()).isEqualTo("nabc");
        assertThat(((RSAKey) copy.getJWKSet().getKeys().get(0)).getPublicExponent().toString()).isEqualTo("eabc");
        assertThat(copy.getJWKSet().getKeys()).hasSize(1);
        assertThat(copy.getSoftwareID()).isEqualTo(softwareID);
        assertThat(copy.getSoftwareVersion()).isEqualTo(softwareVersion);
        assertThat(copy.getTLSClientCertificateBoundAccessTokens()).isTrue();
        assertThat(copy.getMutualTLSSenderConstrainedAccessTokens()).isTrue();
        assertThat(copy.getTLSClientAuthSubjectDN()).isEqualTo(subjectDN);
        assertThat(copy.getTLSClientAuthSanDNS()).isEqualTo(sanDNS);
        assertThat(copy.getTLSClientAuthSanURI()).isEqualTo(sanURI);
        assertThat(copy.getTLSClientAuthSanIP()).isEqualTo(sanIP);
        assertThat(copy.getTLSClientAuthSanEmail()).isEqualTo(sanEmail);
        assertThat(copy.getAuthorizationJWSAlg()).isEqualTo(authzJWSAlg);
        assertThat(copy.getAuthorizationJWEAlg()).isEqualTo(authzJWEAlg);
        assertThat(copy.getAuthorizationJWEEnc()).isEqualTo(authzJWEEnc);

        assertThat(copy.getCustomFields().isEmpty()).isTrue();
    }

    @Test
    public void testApplyDefaults()
            throws Exception {

        ClientMetadata meta = new ClientMetadata();

        assertThat(meta.getResponseTypes()).isNull();
        assertThat(meta.getGrantTypes()).isNull();
        assertThat(meta.getTokenEndpointAuthMethod()).isNull();

        meta.applyDefaults();

        Set<ResponseType> rts = meta.getResponseTypes();
        assertThat(rts).contains(ResponseType.parse("code"));

        Set<GrantType> grantTypes = meta.getGrantTypes();
        assertThat(grantTypes).contains(GrantType.AUTHORIZATION_CODE);

        assertThat(meta.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        // JARM
        assertThat(meta.getAuthorizationJWSAlg()).isNull();
        assertThat(meta.getAuthorizationJWEAlg()).isNull();
        assertThat(meta.getAuthorizationJWEEnc()).isNull();
    }

    @Test
    public void testApplyDefaults_JARM_implicitJWEEnc()
            throws Exception {

        ClientMetadata meta = new ClientMetadata();
        meta.setAuthorizationJWEAlg(JWEAlgorithm.ECDH_ES);

        meta.applyDefaults();

        Set<ResponseType> rts = meta.getResponseTypes();
        assertThat(rts).contains(ResponseType.parse("code"));

        Set<GrantType> grantTypes = meta.getGrantTypes();
        assertThat(grantTypes).contains(GrantType.AUTHORIZATION_CODE);

        assertThat(meta.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        // JARM
        assertThat(meta.getAuthorizationJWSAlg()).isNull();
        assertThat(meta.getAuthorizationJWEAlg()).isEqualTo(JWEAlgorithm.ECDH_ES);
        assertThat(meta.getAuthorizationJWEEnc()).isEqualTo(EncryptionMethod.A128CBC_HS256);
    }

    @Test
    public void testCustomFields()
            throws Exception {

        ClientMetadata meta = new ClientMetadata();

        meta.setCustomField("x-data", "123");

        assertThat( meta.getCustomField("x-data")).isEqualTo("123");
        assertThat( meta.getCustomFields().getString("x-data")).isEqualTo("123");
        assertThat(meta.getCustomFields()).hasSize(1);

        String json = meta.toJSONObject().build().toString();

        meta = ClientMetadata.parse(JSONObjectUtils.parse(json));

        assertThat(meta.getCustomField("x-data")).isEqualTo("123");
        assertThat( meta.getCustomFields().getString("x-data")).isEqualTo("123");
        assertThat(meta.getCustomFields()).hasSize(1);
    }

    @Test
    public void testSetSingleRedirectURI()
            throws Exception {

        ClientMetadata meta = new ClientMetadata();

        URI uri = new URI("https://client.com/callback");

        meta.setRedirectionURI(uri);

        assertThat(meta.getRedirectionURIs()).contains(uri);
        assertThat(meta.getRedirectionURIs()).hasSize(1);

        meta.setRedirectionURI(null);
        assertThat(meta.getRedirectionURIs()).isNull();
    }

    @Test
    public void testSetNullRedirectURI() {

        ClientMetadata meta = new ClientMetadata();
        meta.setRedirectionURI(null);
        assertThat(meta.getRedirectionURIs()).isNull();
        assertThat(meta.getRedirectionURIStrings()).isNull();

        meta.setRedirectionURI(URI.create("https://example.com/cb"));
        assertThat(meta.getRedirectionURIs().iterator().next().toString()).isEqualTo("https://example.com/cb");

        meta.setRedirectionURI(null);
        assertThat(meta.getRedirectionURIs()).isNull();
        assertThat(meta.getRedirectionURIStrings()).isNull();
    }

    @Test
    public void testSetNullRedirectURIs() {

        ClientMetadata meta = new ClientMetadata();
        meta.setRedirectionURIs(null);
        assertThat(meta.getRedirectionURIs()).isNull();
        assertThat(meta.getRedirectionURIStrings()).isNull();

        meta.setRedirectionURIs(Collections.singleton(URI.create("https://example.com/cb")));
        assertThat(meta.getRedirectionURIs().iterator().next().toString()).isEqualTo("https://example.com/cb");

        meta.setRedirectionURIs(null);
        assertThat(meta.getRedirectionURIs()).isNull();
        assertThat(meta.getRedirectionURIStrings()).isNull();
    }

    @Test
    public void testGetRedirectionURIStrings()
            throws Exception {

        ClientMetadata meta = new ClientMetadata();

        assertThat(meta.getRedirectionURIStrings()).isNull();

        Set<URI> redirectURIs = new HashSet<>();
        redirectURIs.add(new URI("https://cliemt.com/cb-1"));
        redirectURIs.add(new URI("https://cliemt.com/cb-2"));
        redirectURIs.add(new URI("https://cliemt.com/cb-3"));

        meta.setRedirectionURIs(redirectURIs);

        assertThat(meta.getRedirectionURIStrings()).contains("https://cliemt.com/cb-1");
        assertThat(meta.getRedirectionURIStrings()).contains("https://cliemt.com/cb-2");
        assertThat(meta.getRedirectionURIStrings()).contains("https://cliemt.com/cb-3");
        assertThat(meta.getRedirectionURIStrings()).hasSize(3);

        meta.setRedirectionURI(new URI("https://cliemt.com/cb"));
        assertThat(meta.getRedirectionURIStrings()).contains("https://cliemt.com/cb");
        assertThat(meta.getRedirectionURIStrings()).hasSize(1);
    }

    @Test
    public void testParse()
            throws Exception {

        String json = "{\n" +
                "      \"redirect_uris\":[\n" +
                "        \"https://client.example.org/callback\",\n" +
                "        \"https://client.example.org/callback2\"],\n" +
                "      \"token_endpoint_auth_method\":\"client_secret_basic\",\n" +
                "      \"example_extension_parameter\": \"example_value\"\n" +
                "     }";

        ClientMetadata meta = ClientMetadata.parse(JSONObjectUtils.parse(json));

        assertThat(meta.getRedirectionURIs()).contains(new URI("https://client.example.org/callback"));
        assertThat(meta.getRedirectionURIs()).contains(new URI("https://client.example.org/callback2"));
        assertThat(meta.getRedirectionURIs()).hasSize(2);

        assertThat(meta.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        assertThat(meta.getCustomField("example_extension_parameter")).isEqualTo("example_value");
    }

    @Test
    public void testParseBadRedirectionURI()
            throws Exception {

        String json = "{\n" +
                " \"redirect_uris\":[\n" +
                "   \"https://\",\n" +
                "   \"https://client.example.org/callback2\"],\n" +
                " \"token_endpoint_auth_method\":\"client_secret_basic\",\n" +
                " \"example_extension_parameter\": \"example_value\"\n" +
                "}";

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> ClientMetadata.parse(JSONObjectUtils.parse(json)));

        assertThat(exception.getMessage()).isEqualTo("Invalid \"redirect_uris\" parameter: Expected authority at index 8: https://");
        assertThat(exception.getErrorObject().getCode()).isEqualTo(RegistrationError.INVALID_REDIRECT_URI.getCode());
        assertThat(exception.getErrorObject().getDescription()).isEqualTo("Invalid redirection URI(s): Expected authority at index 8: https://");

    }

    @Test
    public void testClientCredentialsGrant()
            throws Exception {

		JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("client_name", "Test App");
		builder.add("grant_types", JSONObjectUtils.asJsonArray(Collections.singletonList("client_credentials")));
		builder.add("response_types",JSONObjectUtils.asJsonArray( new ArrayList<>()));
		builder.add("scope", "read write");

        String json = builder.build().toString();

        ClientMetadata metadata = ClientMetadata.parse(JSONObjectUtils.parse(json));

        assertThat(metadata.getName()).isEqualTo("Test App");
        assertThat(metadata.getGrantTypes()).contains(GrantType.CLIENT_CREDENTIALS);
        assertThat(metadata.getGrantTypes()).hasSize(1);
        assertThat(metadata.getResponseTypes().isEmpty()).isTrue();
        assertThat(Scope.parse("read write").containsAll(metadata.getScope())).isTrue();
        assertThat(metadata.getScope()).hasSize(2);

        assertThat(metadata.getTokenEndpointAuthMethod()).isNull();

        metadata.applyDefaults();

        assertThat(metadata.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    @Test
    public void testPasswordGrant()
            throws Exception {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("client_name", "Test App");
        builder.add("grant_types", JSONObjectUtils.asJsonArray(Collections.singletonList("password")));
        builder.add("response_types", JSONObjectUtils.asJsonArray(new ArrayList<>()));
        builder.add("scope", "read write");

        String json = builder.build().toString();

        ClientMetadata metadata = ClientMetadata.parse(JSONObjectUtils.parse(json));

        assertThat(metadata.getName()).isEqualTo("Test App");
        assertThat(metadata.getGrantTypes()).contains(GrantType.PASSWORD);
        assertThat(metadata.getGrantTypes()).hasSize(1);
        assertThat(metadata.getResponseTypes().isEmpty()).isTrue();
        assertThat(Scope.parse("read write").containsAll(metadata.getScope())).isTrue();
        assertThat(metadata.getScope()).hasSize(2);

        assertThat(metadata.getTokenEndpointAuthMethod()).isNull();

        metadata.applyDefaults();

        assertThat(metadata.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    @Test
    public void testNoGrant()
            throws Exception {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("client_name", "Test App");
        builder.add("grant_types", JSONObjectUtils.asJsonArray(new ArrayList<>()));
        builder.add("response_types", JSONObjectUtils.asJsonArray(new ArrayList<>()));
        builder.add("scope", "read write");

        String json = builder.build().toString();

        ClientMetadata metadata = ClientMetadata.parse(JSONObjectUtils.parse(json));

        assertThat(metadata.getName()).isEqualTo("Test App");
        assertThat(metadata.getGrantTypes().isEmpty()).isTrue();
        assertThat(metadata.getResponseTypes().isEmpty()).isTrue();
        assertThat(Scope.parse("read write").containsAll(metadata.getScope())).isTrue();
        assertThat(metadata.getScope()).hasSize(2);

        assertThat(metadata.getTokenEndpointAuthMethod()).isNull();

        metadata.applyDefaults();

        assertThat(metadata.getGrantTypes().isEmpty()).isTrue();
        assertThat(metadata.getResponseTypes().isEmpty()).isTrue();

        assertThat(metadata.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    @Test
    public void testClientAuthNoneWithImplicitGrant() {

        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setGrantTypes(Collections.singleton(GrantType.IMPLICIT));
        clientMetadata.setResponseTypes(Collections.singleton(new ResponseType("token")));

        clientMetadata.applyDefaults();

        assertThat(clientMetadata.getGrantTypes()).isEqualTo(Collections.singleton(GrantType.IMPLICIT));
        assertThat(clientMetadata.getResponseTypes()).isEqualTo(Collections.singleton(new ResponseType("token")));
        assertThat(clientMetadata.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
    }

    @Test
    public void testRejectFragmentInRedirectURI() {

        URI redirectURIWithFragment = URI.create("https://example.com/cb#fragment");

        ClientMetadata metadata = new ClientMetadata();

        // single setter
        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> metadata.setRedirectionURI(redirectURIWithFragment));
        assertThat(exception.getMessage()).isEqualTo("The redirect_uri must not contain fragment");

        // collection setter
        IllegalArgumentException exception2 = Assertions.assertThrows(IllegalArgumentException.class, () -> metadata.setRedirectionURIs(Collections.singleton(redirectURIWithFragment)));
        assertThat(exception2.getMessage()).isEqualTo("The redirect_uri must not contain fragment");


        // static parse method
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("redirect_uris", JSONObjectUtils.asJsonArray(Collections.singletonList(redirectURIWithFragment.toString())));

        OAuth2JSONParseException exception3 = Assertions.assertThrows(OAuth2JSONParseException.class, () -> ClientMetadata.parse(builder.build()));
        assertThat(exception3.getMessage()).isEqualTo("Invalid \"redirect_uris\" parameter: URI must not contain fragment");
        assertThat(exception3.getErrorObject().getCode()).isEqualTo(RegistrationError.INVALID_REDIRECT_URI.getCode());
        assertThat(exception3.getErrorObject().getDescription()).isEqualTo("Invalid redirection URI(s): URI must not contain fragment");

    }

    @Test
    public void testInvalidMetadataError() {

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("response_types", 123);


        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> ClientMetadata.parse(builder.build()));

        assertThat(exception.getMessage()).isEqualTo("Unexpected type of JSON object member with key \"response_types\"");
        assertThat(exception.getErrorObject().getCode()).isEqualTo(RegistrationError.INVALID_CLIENT_METADATA.getCode());
        assertThat(exception.getErrorObject().getDescription()).isEqualTo("Invalid client metadata field: Unexpected type of JSON object member with key \"response_types\"");

    }

    @Test
    public void testPermitParseNullValues()
            throws Exception {

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();

        for (String paramName : ClientMetadata.getRegisteredParameterNames()) {

            jsonObject.addNull(paramName);
        }

        ClientMetadata.parse(jsonObject.build());
    }

    @Test
    public void testIgnoreInvalidEmailOnGetContacts() {

        ClientMetadata clientMetadata = new ClientMetadata();
        List<String> invalidEmail = Collections.singletonList("invalid-email-address");
        clientMetadata.setEmailContacts(invalidEmail);
        assertThat(clientMetadata.getContacts().get(0).toString()).isEqualTo(invalidEmail.get(0));
        assertThat(clientMetadata.getContacts()).hasSize(invalidEmail.size());
    }

    @Test
    public void testSetContactsNull_deprecated() {

        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setContacts(null);
        assertThat(clientMetadata.getContacts()).isNull();
        assertThat(clientMetadata.getEmailContacts()).isNull();
    }

    @Test
    public void testGetContactsNullItem_deprecated() {

        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setEmailContacts(Arrays.asList("alice@wonderland.net", "bob@wonderland.net", null));

        List<InternetAddress> emails = clientMetadata.getContacts();
        assertThat(emails.get(0).getAddress()).isEqualTo("alice@wonderland.net");
        assertThat(emails.get(1).getAddress()).isEqualTo("bob@wonderland.net");
        assertThat(emails).hasSize(2);
    }

    @Test
    public void testGetOneRedirectionURI() {

        ClientMetadata clientMetadata = new ClientMetadata();

        assertThat(clientMetadata.getRedirectionURI()).isNull();

        URI uri1 = URI.create("https://example.com/cb-1");
        clientMetadata.setRedirectionURI(uri1);
        assertThat(clientMetadata.getRedirectionURI()).isEqualTo(uri1);

        URI uri2 = URI.create("https://example.com/cb-2");
        Set<URI> uriSet = new HashSet<>(Arrays.asList(uri1, uri2));
        clientMetadata.setRedirectionURIs(uriSet);
        assertThat(uriSet).contains(clientMetadata.getRedirectionURI());
    }

    @Test
    public void testCustomParameters()
            throws OAuth2JSONParseException {

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();
        jsonObject.add("grant_types", JSONObjectUtils.asJsonArray(Collections.singletonList("code")));
        jsonObject.add("preferred_client_id", "123");
        jsonObject.add("preferred_client_secret", "ahp7Thaeh4iedagohhaeThuhu9ahreiw");

        ClientMetadata clientMetadata = ClientMetadata.parse(jsonObject.build());

        assertThat(clientMetadata.getCustomField("preferred_client_id")).isEqualTo("123");
        assertThat(clientMetadata.getCustomField("preferred_client_secret")).isEqualTo("ahp7Thaeh4iedagohhaeThuhu9ahreiw");
    }

    @Test
    public void testJARM()
            throws OAuth2JSONParseException {

        ClientMetadata clientMetadata = new ClientMetadata();

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

        clientMetadata = ClientMetadata.parse(jsonObject);

        assertThat(clientMetadata.getAuthorizationJWSAlg()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(clientMetadata.getAuthorizationJWEAlg()).isEqualTo(JWEAlgorithm.ECDH_ES);
        assertThat(clientMetadata.getAuthorizationJWEEnc()).isEqualTo(EncryptionMethod.A256GCM);
    }

    @Test
    public void testJARM_rejectNoneJWSAlg() {

        ClientMetadata clientMetadata = new ClientMetadata();

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> clientMetadata.setAuthorizationJWSAlg(new JWSAlgorithm("none")));

        assertThat(exception.getMessage()).isEqualTo("The JWS algorithm must not be \"none\"");

    }

    @Test
    public void testRequireOneTLSSubjectParam() {

        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH);
        clientMetadata.applyDefaults();

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> ClientMetadata.parse(clientMetadata.toJSONObject().build()));

        assertThat(exception.getMessage()).isEqualTo("A certificate field must be specified to indicate the subject in tls_client_auth: " +
                "tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip or tls_client_auth_san_email");
        assertThat(exception.getErrorObject().getCode()).isEqualTo("invalid_client_metadata");
        assertThat(exception.getErrorObject().getDescription()).isEqualTo("Invalid client metadata field: " +
                "A certificate field must be specified to indicate the subject in tls_client_auth: " +
                "tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip or tls_client_auth_san_email");

    }

    /* FIXME
    @Test
    public void testRejectMoreThanOneTLSSubjectParam() {

        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH);
        clientMetadata.applyDefaults();

        List<String> certParams = new LinkedList<>();
        certParams.add("tls_client_auth_subject_dn");
        certParams.add("tls_client_auth_san_dns");
        certParams.add("tls_client_auth_san_uri");
        certParams.add("tls_client_auth_san_ip");
        certParams.add("tls_client_auth_san_email");

        String expectedMessage = "Exactly one certificate field must be specified to indicate the subject in tls_client_auth: " +
                "tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip or tls_client_auth_san_email";

        for (int subsetSize : new int[]{2, 3, 4, 5}) {

            for (int[] combi : new Combinations(certParams.size(), subsetSize)) {

                JsonObject jsonObject = clientMetadata.toJSONObject().build();
                for (int i : combi) {
                    jsonObject.put(certParams.get(i), Json.createValue("value"));
                }
                try {
                    ClientMetadata.parse(jsonObject);
                    fail(jsonObject.toString());
                } catch (OAuth2JSONParseException e) {
                    assertThat(e.getMessage()).isEqualTo(expectedMessage);
                    assertThat(e.getErrorObject().getCode()).isEqualTo("invalid_client_metadata");
                    assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid client metadata field: " + expectedMessage);
                }
            }
        }
    }

     */
}