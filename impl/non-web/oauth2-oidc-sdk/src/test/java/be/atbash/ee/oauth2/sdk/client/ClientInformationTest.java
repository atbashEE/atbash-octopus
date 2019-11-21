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

package be.atbash.ee.oauth2.sdk.client;


import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.Test;

import javax.json.JsonObject;
import java.net.URI;
import java.util.Date;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the client information class.
 */
public class ClientInformationTest {

    @Test
    public void testRegisteredParameters() {

        Set<String> paramNames = ClientInformation.getRegisteredParameterNames();

        assertThat(paramNames).contains("client_id");
        assertThat(paramNames).contains("client_id_issued_at");
        assertThat(paramNames).contains("registration_access_token");
        assertThat(paramNames).contains("registration_client_uri");
        assertThat(paramNames).contains("client_secret");
        assertThat(paramNames).contains("client_secret_expires_at");

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

        assertThat(paramNames).hasSize(35);
    }

    @Test
    public void testMinimalConstructor()
            throws Exception {

        ClientID clientID = new ClientID("123");
        ClientMetadata metadata = new ClientMetadata();
        metadata.setName("Example app");

        ClientInformation info = new ClientInformation(clientID, null, metadata, null);

        assertThat(info.getID()).isEqualTo(clientID);
        assertThat(info.getIDIssueDate()).isNull();
        assertThat(info.getMetadata()).isEqualTo(metadata);
        assertThat(info.getMetadata().getName()).isEqualTo("Example app");
        assertThat(info.getSecret()).isNull();
        assertThat(info.getRegistrationURI()).isNull();
        assertThat(info.getRegistrationAccessToken()).isNull();

        String json = info.toJSONObject().toString();

        info = ClientInformation.parse(JSONObjectUtils.parse(json));

        assertThat(info.getID()).isEqualTo(clientID);
        assertThat(info.getIDIssueDate()).isNull();
        assertThat(info.getMetadata().getName()).isEqualTo("Example app");
        assertThat(info.getSecret()).isNull();
        assertThat(info.getRegistrationURI()).isNull();
        assertThat(info.getRegistrationAccessToken()).isNull();

        Date now = new Date(new Date().getTime() / 1000 * 1000);
        Secret secret = new Secret("secret");

        info = new ClientInformation(clientID, now, metadata, secret);

        assertThat(info.getID()).isEqualTo(clientID);
        assertThat(info.getIDIssueDate()).isEqualTo(now);
        assertThat(info.getMetadata()).isEqualTo(metadata);
        assertThat(info.getMetadata().getName()).isEqualTo("Example app");
        assertThat(info.getSecret()).isEqualTo(secret);
        assertThat(info.getRegistrationURI()).isNull();
        assertThat(info.getRegistrationAccessToken()).isNull();

        json = info.toJSONObject().toString();

        info = ClientInformation.parse(JSONObjectUtils.parse(json));

        assertThat(info.getID()).isEqualTo(clientID);
        assertThat(info.getIDIssueDate()).isEqualTo(now);
        assertThat(info.getMetadata().getName()).isEqualTo("Example app");
        assertThat(info.getSecret()).isEqualTo(secret);
        assertThat(info.getRegistrationURI()).isNull();
        assertThat(info.getRegistrationAccessToken()).isNull();
    }

    @Test
    public void testFullConstructor()
            throws Exception {

        ClientID clientID = new ClientID("123");
        ClientMetadata metadata = new ClientMetadata();
        metadata.setName("Example app");

        ClientInformation info = new ClientInformation(clientID, null, metadata, null, null, null);

        assertThat(info.getID()).isEqualTo(clientID);
        assertThat(info.getIDIssueDate()).isNull();
        assertThat(info.getMetadata()).isEqualTo(metadata);
        assertThat(info.getMetadata().getName()).isEqualTo("Example app");
        assertThat(info.getSecret()).isNull();
        assertThat(info.getRegistrationURI()).isNull();
        assertThat(info.getRegistrationAccessToken()).isNull();

        String json = info.toJSONObject().toString();

        info = ClientInformation.parse(JSONObjectUtils.parse(json));

        assertThat(info.getID()).isEqualTo(clientID);
        assertThat(info.getIDIssueDate()).isNull();
        assertThat(info.getMetadata().getName()).isEqualTo("Example app");
        assertThat(info.getSecret()).isNull();
        assertThat(info.getRegistrationURI()).isNull();
        assertThat(info.getRegistrationAccessToken()).isNull();

        Date now = new Date(new Date().getTime() / 1000 * 1000);
        Secret secret = new Secret("secret");
        URI regURI = new URI("https://c2id.com/client-reg/123");
        BearerAccessToken accessToken = new BearerAccessToken("xyz");

        info = new ClientInformation(clientID, now, metadata, secret, regURI, accessToken);

        assertThat(info.getID()).isEqualTo(clientID);
        assertThat(info.getIDIssueDate()).isEqualTo(now);
        assertThat(info.getMetadata()).isEqualTo(metadata);
        assertThat(info.getMetadata().getName()).isEqualTo("Example app");
        assertThat(info.getSecret()).isEqualTo(secret);
        assertThat(info.getRegistrationURI()).isEqualTo(regURI);
        assertThat(info.getRegistrationAccessToken()).isEqualTo(accessToken);

        json = info.toJSONObject().toString();

        info = ClientInformation.parse(JSONObjectUtils.parse(json));

        assertThat(info.getID()).isEqualTo(clientID);
        assertThat(info.getIDIssueDate()).isEqualTo(now);
        assertThat(info.getMetadata().getName()).isEqualTo("Example app");
        assertThat(info.getSecret()).isEqualTo(secret);
        assertThat(info.getRegistrationURI()).isEqualTo(regURI);
        assertThat(info.getRegistrationAccessToken()).isEqualTo(accessToken);
    }

    @Test
    public void testNoSecretExpiration()
            throws Exception {

        ClientID clientID = new ClientID("123");
        ClientMetadata metadata = new ClientMetadata();
        metadata.setRedirectionURI(new URI("https://example.com/in"));
        Secret secret = new Secret("secret");
        assertThat(secret.expired()).isFalse();

        ClientInformation clientInfo = new ClientInformation(clientID, null, metadata, secret);

        assertThat(clientInfo.getID()).isEqualTo(clientID);
        assertThat(clientInfo.getIDIssueDate()).isNull();
        assertThat(clientInfo.getMetadata()).isEqualTo(metadata);
        assertThat(clientInfo.getSecret()).isEqualTo(secret);
        assertThat(clientInfo.getSecret().expired()).isFalse();
        assertThat(clientInfo.getRegistrationURI()).isNull();
        assertThat(clientInfo.getRegistrationAccessToken()).isNull();

        JsonObject jsonObject = clientInfo.toJSONObject();
        assertThat(jsonObject.getString("client_id")).isEqualTo("123");
        assertThat((JSONObjectUtils.getStringList(jsonObject, "redirect_uris")).get(0)).isEqualTo("https://example.com/in");
        assertThat(jsonObject.getString("client_secret")).isEqualTo("secret");
        assertThat(jsonObject.getJsonNumber("client_secret_expires_at").longValue()).isEqualTo(0L);
        assertThat(jsonObject.getBoolean("tls_client_certificate_bound_access_tokens")).isFalse();
        assertThat(jsonObject).hasSize(5);

        String jsonString = jsonObject.toString();

        jsonObject = JSONObjectUtils.parse(jsonString);

        clientInfo = ClientInformation.parse(jsonObject);

        assertThat(clientInfo.getID().toString()).isEqualTo("123");
        assertThat(clientInfo.getIDIssueDate()).isNull();
        assertThat(clientInfo.getMetadata().getRedirectionURIs().iterator().next().toString()).isEqualTo("https://example.com/in");
        assertThat(clientInfo.getSecret().getValue()).isEqualTo("secret");
        assertThat(clientInfo.getSecret().expired()).isFalse();
        assertThat(clientInfo.getSecret().getExpirationDate()).isNull();
        assertThat(clientInfo.getRegistrationURI()).isNull();
        assertThat(clientInfo.getRegistrationAccessToken()).isNull();
    }

    @Test
    public void testNoSecretExpirationAlt()
            throws Exception {

        ClientID clientID = new ClientID("123");
        ClientMetadata metadata = new ClientMetadata();
        metadata.setRedirectionURI(new URI("https://example.com/in"));
        Secret secret = new Secret("secret", null);
        assertThat(secret.expired()).isFalse();

        ClientInformation clientInfo = new ClientInformation(clientID, null, metadata, secret);

        assertThat(clientInfo.getID()).isEqualTo(clientID);
        assertThat(clientInfo.getIDIssueDate()).isNull();
        assertThat(clientInfo.getMetadata()).isEqualTo(metadata);
        assertThat(clientInfo.getSecret()).isEqualTo(secret);
        assertThat(clientInfo.getSecret().expired()).isFalse();
        assertThat(clientInfo.getRegistrationURI()).isNull();
        assertThat(clientInfo.getRegistrationAccessToken()).isNull();

        JsonObject jsonObject = clientInfo.toJSONObject();
        assertThat(jsonObject.getString("client_id")).isEqualTo("123");
        assertThat(JSONObjectUtils.getStringList(jsonObject, "redirect_uris").get(0)).isEqualTo("https://example.com/in");
        assertThat(jsonObject.getString("client_secret")).isEqualTo("secret");
        assertThat(jsonObject.getJsonNumber("client_secret_expires_at").longValue()).isEqualTo(0L);
        assertThat(jsonObject.getBoolean("tls_client_certificate_bound_access_tokens")).isFalse();
        assertThat(jsonObject).hasSize(5);

        String jsonString = jsonObject.toString();

        jsonObject = JSONObjectUtils.parse(jsonString);

        clientInfo = ClientInformation.parse(jsonObject);

        assertThat(clientInfo.getID().toString()).isEqualTo("123");
        assertThat(clientInfo.getIDIssueDate()).isNull();
        assertThat(clientInfo.getMetadata().getRedirectionURIs().iterator().next().toString()).isEqualTo("https://example.com/in");
        assertThat(clientInfo.getSecret().getValue()).isEqualTo("secret");
        assertThat(clientInfo.getSecret().getExpirationDate()).isNull();
        assertThat(clientInfo.getSecret().expired()).isFalse();
        assertThat(clientInfo.getRegistrationURI()).isNull();
        assertThat(clientInfo.getRegistrationAccessToken()).isNull();
    }

    @Test
    public void testInferConfidentialClientType() {

        ClientID clientID = new ClientID();
        Date issueDate = new Date();
        ClientMetadata metadata = new ClientMetadata();
        metadata.applyDefaults();
        Secret secret = new Secret();


        ClientInformation client;

        // default
        client = new ClientInformation(clientID, issueDate, metadata, secret);
        assertThat(client.inferClientType()).isEqualTo(ClientType.CONFIDENTIAL);

        // basic auth
        metadata = new ClientMetadata();
        metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        metadata.applyDefaults();

        client = new ClientInformation(clientID, issueDate, metadata, secret);
        assertThat(client.inferClientType()).isEqualTo(ClientType.CONFIDENTIAL);

        // basic post auth
        metadata = new ClientMetadata();
        metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
        metadata.applyDefaults();

        client = new ClientInformation(clientID, issueDate, metadata, secret);
        assertThat(client.inferClientType()).isEqualTo(ClientType.CONFIDENTIAL);

        // secret JWT auth
        metadata = new ClientMetadata();
        metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
        metadata.applyDefaults();

        client = new ClientInformation(clientID, issueDate, metadata, secret);
        assertThat(client.inferClientType()).isEqualTo(ClientType.CONFIDENTIAL);

        // private key JWT auth - JWK by ref
        metadata = new ClientMetadata();
        metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        metadata.setJWKSetURI(URI.create("https://example.com/jwks.json"));
        metadata.applyDefaults();

        client = new ClientInformation(clientID, issueDate, metadata, secret);
        assertThat(client.inferClientType()).isEqualTo(ClientType.CONFIDENTIAL);

        // private key JWT auth - JWK by value
        metadata = new ClientMetadata();
        metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        metadata.setJWKSet(new JWKSet());
        metadata.applyDefaults();

        client = new ClientInformation(clientID, issueDate, metadata, secret);
        assertThat(client.inferClientType()).isEqualTo(ClientType.CONFIDENTIAL);

        // private key JWT auth - unspecified key source
        metadata = new ClientMetadata();
        metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        metadata.setJWKSet(new JWKSet());
        metadata.applyDefaults();

        client = new ClientInformation(clientID, issueDate, metadata, secret);
        assertThat(client.inferClientType()).isEqualTo(ClientType.CONFIDENTIAL);

        // secret set, but token endpoint auth method = null
        metadata = new ClientMetadata();

        client = new ClientInformation(clientID, issueDate, metadata, secret);
        assertThat(client.inferClientType()).isEqualTo(ClientType.CONFIDENTIAL);

        // secret = null, token endpoint auth method = null
        metadata = new ClientMetadata();

        client = new ClientInformation(clientID, issueDate, metadata, null);
        assertThat(client.inferClientType()).isEqualTo(ClientType.CONFIDENTIAL);
    }

    @Test
    public void testInferPublicClientType() {

        ClientID clientID = new ClientID();
        Date issueDate = new Date();
        ClientMetadata metadata = new ClientMetadata();
        metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.NONE);
        metadata.applyDefaults();
        Secret secret = null;

        ClientInformation client;

        client = new ClientInformation(clientID, issueDate, metadata, secret);
        assertThat(client.inferClientType()).isEqualTo(ClientType.PUBLIC);
    }
}
