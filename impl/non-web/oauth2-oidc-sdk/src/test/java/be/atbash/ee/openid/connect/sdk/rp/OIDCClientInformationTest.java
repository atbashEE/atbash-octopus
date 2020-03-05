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


import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Date;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the OpenID Connect client information class.
 */
public class OIDCClientInformationTest {

    @Test
    public void testRegisteredParameters() {

        Set<String> paramNames = OIDCClientInformation.getRegisteredParameterNames();

        assertThat(paramNames.contains("client_id")).isTrue();
        assertThat(paramNames.contains("client_id_issued_at")).isTrue();
        assertThat(paramNames.contains("registration_access_token")).isTrue();
        assertThat(paramNames.contains("registration_client_uri")).isTrue();
        assertThat(paramNames.contains("client_secret")).isTrue();
        assertThat(paramNames.contains("client_secret_expires_at")).isTrue();

        assertThat(paramNames.contains("redirect_uris")).isTrue();
        assertThat(paramNames.contains("client_name")).isTrue();
        assertThat(paramNames.contains("client_uri")).isTrue();
        assertThat(paramNames.contains("logo_uri")).isTrue();
        assertThat(paramNames.contains("contacts")).isTrue();
        assertThat(paramNames.contains("tos_uri")).isTrue();
        assertThat(paramNames.contains("policy_uri")).isTrue();
        assertThat(paramNames.contains("token_endpoint_auth_method")).isTrue();
        assertThat(paramNames.contains("scope")).isTrue();
        assertThat(paramNames.contains("grant_types")).isTrue();
        assertThat(paramNames.contains("response_types")).isTrue();
        assertThat(paramNames.contains("jwks_uri")).isTrue();
        assertThat(paramNames.contains("jwks")).isTrue();
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
        assertThat(paramNames.contains("request_object_signing_alg")).isTrue();
        assertThat(paramNames.contains("token_endpoint_auth_signing_alg")).isTrue();
        assertThat(paramNames.contains("default_max_age")).isTrue();
        assertThat(paramNames.contains("require_auth_time")).isTrue();
        assertThat(paramNames.contains("default_acr_values")).isTrue();
        assertThat(paramNames.contains("initiate_login_uri")).isTrue();
        assertThat(paramNames.contains("request_uris")).isTrue();
        assertThat(paramNames.contains("post_logout_redirect_uris")).isTrue();
        assertThat(paramNames.contains("frontchannel_logout_uri")).isTrue();
        assertThat(paramNames.contains("frontchannel_logout_session_required")).isTrue();
        assertThat(paramNames.contains("backchannel_logout_uri")).isTrue();
        assertThat(paramNames.contains("backchannel_logout_session_required")).isTrue();

        assertThat(paramNames).hasSize(53);
    }

    @Test
    public void testConstructor()
            throws Exception {

        ClientID clientID = new ClientID("123");
        Date now = new Date(new Date().getTime() / 1000 * 1000);
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setName("Example app");
        Secret secret = new Secret("secret");
        URI regURI = new URI("https://c2id.com/client-reg/123");
        BearerAccessToken accessToken = new BearerAccessToken("xyz");

        OIDCClientInformation info = new OIDCClientInformation(clientID, now, metadata, secret, regURI, accessToken);

        assertThat(info.getID()).isEqualTo(clientID);
        assertThat(info.getIDIssueDate()).isEqualTo(now);
        assertThat(info.getMetadata()).isEqualTo(metadata);
        assertThat(info.getOIDCMetadata()).isEqualTo(metadata);
        assertThat(info.getMetadata().getName()).isEqualTo("Example app");
        assertThat(info.getSecret()).isEqualTo(secret);
        assertThat(info.getRegistrationURI()).isEqualTo(regURI);
        assertThat(info.getRegistrationAccessToken()).isEqualTo(accessToken);

        String json = info.toJSONObject().toString();

        info = OIDCClientInformation.parse(JSONObjectUtils.parse(json));

        assertThat(info.getID()).isEqualTo(clientID);
        assertThat(info.getIDIssueDate()).isEqualTo(now);
        assertThat(info.getMetadata().getName()).isEqualTo("Example app");
        assertThat(info.getOIDCMetadata().getName()).isEqualTo("Example app");
        assertThat(info.getSecret()).isEqualTo(secret);
        assertThat(info.getRegistrationURI()).isEqualTo(regURI);
        assertThat(info.getRegistrationAccessToken()).isEqualTo(accessToken);
    }

    @Test
    public void testNoClientSecretExpiration()
            throws Exception {

        ClientID clientID = new ClientID("123");
        Date now = new Date(new Date().getTime() / 1000 * 1000);
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        Secret secret = new Secret("secret", null);
        URI regURI = new URI("https://c2id.com/client-reg/123");
        BearerAccessToken accessToken = new BearerAccessToken("xyz");

        OIDCClientInformation info = new OIDCClientInformation(clientID, now, metadata, secret, regURI, accessToken);

        assertThat(info.getSecret().expired()).isFalse();

        String jsonString = info.toJSONObject().toString();

        info = OIDCClientInformation.parse(JSONObjectUtils.parse(jsonString));

        assertThat(info.getSecret().expired()).isFalse();
    }
}
