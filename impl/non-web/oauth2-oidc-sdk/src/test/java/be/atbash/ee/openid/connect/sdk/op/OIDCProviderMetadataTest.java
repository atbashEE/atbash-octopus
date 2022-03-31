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
package be.atbash.ee.openid.connect.sdk.op;


import be.atbash.ee.oauth2.sdk.*;
import be.atbash.ee.oauth2.sdk.as.AuthorizationServerEndpointMetadata;
import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.pkce.CodeChallengeMethod;
import be.atbash.ee.openid.connect.sdk.Display;
import be.atbash.ee.openid.connect.sdk.OIDCResponseTypeValue;
import be.atbash.ee.openid.connect.sdk.OIDCScopeValue;
import be.atbash.ee.openid.connect.sdk.SubjectType;
import be.atbash.ee.openid.connect.sdk.claims.ACR;
import be.atbash.ee.openid.connect.sdk.claims.ClaimType;
import be.atbash.ee.openid.connect.sdk.rp.OIDCClientMetadata;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import java.net.URI;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;


public class OIDCProviderMetadataTest {

    @Test
    public void testRegisteredParameters() {

        Set<String> paramNames = OIDCProviderMetadata.getRegisteredParameterNames();

        assertThat(paramNames.contains("issuer")).isTrue();
        assertThat(paramNames.contains("authorization_endpoint")).isTrue();
        assertThat(paramNames.contains("token_endpoint")).isTrue();
        assertThat(paramNames.contains("userinfo_endpoint")).isTrue();
        assertThat(paramNames.contains("jwks_uri")).isTrue();
        assertThat(paramNames.contains("registration_endpoint")).isTrue();
        assertThat(paramNames.contains("scopes_supported")).isTrue();
        assertThat(paramNames.contains("response_types_supported")).isTrue();
        assertThat(paramNames.contains("response_modes_supported")).isTrue();
        assertThat(paramNames.contains("grant_types_supported")).isTrue();
        assertThat(paramNames.contains("code_challenge_methods_supported")).isTrue();
        assertThat(paramNames.contains("acr_values_supported")).isTrue();
        assertThat(paramNames.contains("subject_types_supported")).isTrue();
        assertThat(paramNames.contains("id_token_signing_alg_values_supported")).isTrue();
        assertThat(paramNames.contains("id_token_encryption_alg_values_supported")).isTrue();
        assertThat(paramNames.contains("id_token_encryption_enc_values_supported")).isTrue();
        assertThat(paramNames.contains("userinfo_signing_alg_values_supported")).isTrue();
        assertThat(paramNames.contains("userinfo_encryption_alg_values_supported")).isTrue();
        assertThat(paramNames.contains("userinfo_encryption_enc_values_supported")).isTrue();
        assertThat(paramNames.contains("pushed_authorization_request_endpoint")).isTrue();
        assertThat(paramNames.contains("request_object_endpoint")).isTrue();
        assertThat(paramNames.contains("request_object_signing_alg_values_supported")).isTrue();
        assertThat(paramNames.contains("request_object_encryption_alg_values_supported")).isTrue();
        assertThat(paramNames.contains("request_object_encryption_enc_values_supported")).isTrue();
        assertThat(paramNames.contains("token_endpoint_auth_methods_supported")).isTrue();
        assertThat(paramNames.contains("token_endpoint_auth_signing_alg_values_supported")).isTrue();
        assertThat(paramNames.contains("display_values_supported")).isTrue();
        assertThat(paramNames.contains("claim_types_supported")).isTrue();
        assertThat(paramNames.contains("claims_supported")).isTrue();
        assertThat(paramNames.contains("service_documentation")).isTrue();
        assertThat(paramNames.contains("claims_locales_supported")).isTrue();
        assertThat(paramNames.contains("ui_locales_supported")).isTrue();
        assertThat(paramNames.contains("claims_parameter_supported")).isTrue();
        assertThat(paramNames.contains("request_parameter_supported")).isTrue();
        assertThat(paramNames.contains("request_uri_parameter_supported")).isTrue();
        assertThat(paramNames.contains("require_request_uri_registration")).isTrue();
        assertThat(paramNames.contains("op_policy_uri")).isTrue();
        assertThat(paramNames.contains("op_tos_uri")).isTrue();
        assertThat(paramNames.contains("check_session_iframe")).isTrue();
        assertThat(paramNames.contains("end_session_endpoint")).isTrue();
        assertThat(paramNames.contains("introspection_endpoint")).isTrue();
        assertThat(paramNames.contains("introspection_endpoint_auth_methods_supported")).isTrue();
        assertThat(paramNames.contains("introspection_endpoint_auth_signing_alg_values_supported")).isTrue();
        assertThat(paramNames.contains("revocation_endpoint")).isTrue();
        assertThat(paramNames.contains("revocation_endpoint_auth_methods_supported")).isTrue();
        assertThat(paramNames.contains("revocation_endpoint_auth_signing_alg_values_supported")).isTrue();
        assertThat(paramNames.contains("frontchannel_logout_supported")).isTrue();
        assertThat(paramNames.contains("frontchannel_logout_session_supported")).isTrue();
        assertThat(paramNames.contains("backchannel_logout_supported")).isTrue();
        assertThat(paramNames.contains("backchannel_logout_session_supported")).isTrue();
        assertThat(paramNames.contains("mtls_endpoint_aliases")).isTrue();
        assertThat(paramNames.contains("tls_client_certificate_bound_access_tokens")).isTrue();
        assertThat(paramNames.contains("authorization_signing_alg_values_supported")).isTrue();
        assertThat(paramNames.contains("authorization_encryption_alg_values_supported")).isTrue();
        assertThat(paramNames.contains("authorization_encryption_enc_values_supported")).isTrue();
        assertThat(paramNames.contains("device_authorization_endpoint")).isTrue();

        assertThat(paramNames).hasSize(56);
    }

    @Test
    public void testParseExample() throws Exception {

        String s = "{\n" +
                "   \"issuer\":\n" +
                "     \"https://server.example.com\",\n" +
                "   \"authorization_endpoint\":\n" +
                "     \"https://server.example.com/connect/authorize\",\n" +
                "   \"token_endpoint\":\n" +
                "     \"https://server.example.com/connect/token\",\n" +
                "   \"token_endpoint_auth_methods_supported\":\n" +
                "     [\"client_secret_basic\", \"private_key_jwt\"],\n" +
                "   \"token_endpoint_auth_signing_alg_values_supported\":\n" +
                "     [\"RS256\", \"ES256\"],\n" +
                "   \"userinfo_endpoint\":\n" +
                "     \"https://server.example.com/connect/userinfo\",\n" +
                "   \"check_session_iframe\":\n" +
                "     \"https://server.example.com/connect/check_session\",\n" +
                "   \"end_session_endpoint\":\n" +
                "     \"https://server.example.com/connect/end_session\",\n" +
                "   \"jwks_uri\":\n" +
                "     \"https://server.example.com/jwks.json\",\n" +
                "   \"registration_endpoint\":\n" +
                "     \"https://server.example.com/connect/register\",\n" +
                "   \"scopes_supported\":\n" +
                "     [\"openid\", \"profile\", \"email\", \"address\",\n" +
                "      \"phone\", \"offline_access\"],\n" +
                "   \"response_types_supported\":\n" +
                "     [\"code\", \"code id_token\", \"id_token\", \"token id_token\"],\n" +
                "   \"acr_values_supported\":\n" +
                "     [\"urn:mace:incommon:iap:silver\",\n" +
                "      \"urn:mace:incommon:iap:bronze\"],\n" +
                "   \"subject_types_supported\":\n" +
                "     [\"public\", \"pairwise\"],\n" +
                "   \"userinfo_signing_alg_values_supported\":\n" +
                "     [\"RS256\", \"ES256\", \"HS256\"],\n" +
                "   \"userinfo_encryption_alg_values_supported\":\n" +
                "     [\"A128KW\"],\n" +
                "   \"userinfo_encryption_enc_values_supported\":\n" +
                "     [\"A128CBC-HS256\", \"A128GCM\"],\n" +
                "   \"id_token_signing_alg_values_supported\":\n" +
                "     [\"RS256\", \"ES256\", \"HS256\"],\n" +
                "   \"id_token_encryption_alg_values_supported\":\n" +
                "     [\"A128KW\"],\n" +
                "   \"id_token_encryption_enc_values_supported\":\n" +
                "     [\"A128CBC-HS256\", \"A128GCM\"],\n" +
                "   \"request_object_signing_alg_values_supported\":\n" +
                "     [\"none\", \"RS256\", \"ES256\"],\n" +
                "   \"display_values_supported\":\n" +
                "     [\"page\", \"popup\"],\n" +
                "   \"claim_types_supported\":\n" +
                "     [\"normal\", \"distributed\"],\n" +
                "   \"claims_supported\":\n" +
                "     [\"sub\", \"iss\", \"auth_time\", \"acr\",\n" +
                "      \"name\", \"given_name\", \"family_name\", \"nickname\",\n" +
                "      \"profile\", \"picture\", \"website\",\n" +
                "      \"email\", \"email_verified\", \"locale\", \"zoneinfo\",\n" +
                "      \"http://example.info/claims/groups\"],\n" +
                "   \"claims_parameter_supported\":\n" +
                "     true,\n" +
                "   \"service_documentation\":\n" +
                "     \"http://server.example.com/connect/service_documentation.html\"\n" +
                "  }";

        OIDCProviderMetadata op = OIDCProviderMetadata.parse(s);

        assertThat(op.getIssuer().getValue()).isEqualTo("https://server.example.com");
        assertThat(op.getAuthorizationEndpointURI().toString()).isEqualTo("https://server.example.com/connect/authorize");
        assertThat(op.getTokenEndpointURI().toString()).isEqualTo("https://server.example.com/connect/token");

        List<ClientAuthenticationMethod> authMethods = op.getTokenEndpointAuthMethods();
        assertThat(authMethods.contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)).isTrue();
        assertThat(authMethods.contains(ClientAuthenticationMethod.PRIVATE_KEY_JWT)).isTrue();
        assertThat(authMethods).hasSize(2);

        List<JWSAlgorithm> tokenEndpointJWSAlgs = op.getTokenEndpointJWSAlgs();
        assertThat(tokenEndpointJWSAlgs.contains(JWSAlgorithm.RS256)).isTrue();
        assertThat(tokenEndpointJWSAlgs.contains(JWSAlgorithm.ES256)).isTrue();
        assertThat(tokenEndpointJWSAlgs).hasSize(2);

        assertThat(op.getCodeChallengeMethods()).isNull();

        assertThat(op.getUserInfoEndpointURI().toString()).isEqualTo("https://server.example.com/connect/userinfo");

        assertThat(op.getCheckSessionIframeURI().toString()).isEqualTo("https://server.example.com/connect/check_session");
        assertThat(op.getEndSessionEndpointURI().toString()).isEqualTo("https://server.example.com/connect/end_session");

        assertThat(op.getJWKSetURI().toString()).isEqualTo("https://server.example.com/jwks.json");

        assertThat(op.getRegistrationEndpointURI().toString()).isEqualTo("https://server.example.com/connect/register");
        Scope scopes = op.getScopes();
        assertThat(scopes.contains(OIDCScopeValue.OPENID)).isTrue();
        assertThat(scopes.contains(OIDCScopeValue.PROFILE)).isTrue();
        assertThat(scopes.contains(OIDCScopeValue.EMAIL)).isTrue();
        assertThat(scopes.contains(OIDCScopeValue.ADDRESS)).isTrue();
        assertThat(scopes.contains(OIDCScopeValue.PHONE)).isTrue();
        assertThat(scopes.contains(OIDCScopeValue.OFFLINE_ACCESS)).isTrue();
        assertThat(scopes).hasSize(6);

        List<ResponseType> rts = op.getResponseTypes();
        // [\"code\", \"code id_token\", \"id_token\", \"token id_token\"]
        ResponseType rt1 = new ResponseType();
        rt1.add(ResponseType.Value.CODE);
        assertThat(rts.contains(rt1)).isTrue();

        ResponseType rt2 = new ResponseType();
        rt2.add(ResponseType.Value.CODE);
        rt2.add(OIDCResponseTypeValue.ID_TOKEN);
        assertThat(rts.contains(rt2)).isTrue();

        ResponseType rt3 = new ResponseType();
        rt3.add(OIDCResponseTypeValue.ID_TOKEN);
        assertThat(rts.contains(rt3)).isTrue();

        ResponseType rt4 = new ResponseType();
        rt4.add(ResponseType.Value.TOKEN);
        rt4.add(OIDCResponseTypeValue.ID_TOKEN);
        assertThat(rts.contains(rt4)).isTrue();

        assertThat(rts).hasSize(4);

        List<ACR> acrValues = op.getACRs();
        assertThat(acrValues.contains(new ACR("urn:mace:incommon:iap:silver"))).isTrue();
        assertThat(acrValues.contains(new ACR("urn:mace:incommon:iap:bronze"))).isTrue();
        assertThat(acrValues).hasSize(2);

        List<SubjectType> subjectTypes = op.getSubjectTypes();
        assertThat(subjectTypes.contains(SubjectType.PUBLIC)).isTrue();
        assertThat(subjectTypes.contains(SubjectType.PAIRWISE)).isTrue();
        assertThat(subjectTypes).hasSize(2);

        // UserInfo
        List<JWSAlgorithm> userInfoJWSAlgs = op.getUserInfoJWSAlgs();
        assertThat(userInfoJWSAlgs.contains(JWSAlgorithm.RS256)).isTrue();
        assertThat(userInfoJWSAlgs.contains(JWSAlgorithm.ES256)).isTrue();
        assertThat(userInfoJWSAlgs.contains(JWSAlgorithm.HS256)).isTrue();
        assertThat(userInfoJWSAlgs).hasSize(3);

        List<JWEAlgorithm> userInfoJWEalgs = op.getUserInfoJWEAlgs();
        assertThat(userInfoJWEalgs.contains(JWEAlgorithm.A128KW)).isTrue();
        assertThat(userInfoJWEalgs).hasSize(1);

        List<EncryptionMethod> userInfoEncs = op.getUserInfoJWEEncs();
        assertThat(userInfoEncs.contains(EncryptionMethod.A128CBC_HS256)).isTrue();
        assertThat(userInfoEncs.contains(EncryptionMethod.A128GCM)).isTrue();
        assertThat(userInfoEncs).hasSize(2);

        // ID token
        List<JWSAlgorithm> idTokenJWSAlgs = op.getIDTokenJWSAlgs();
        assertThat(idTokenJWSAlgs.contains(JWSAlgorithm.RS256)).isTrue();
        assertThat(idTokenJWSAlgs.contains(JWSAlgorithm.ES256)).isTrue();
        assertThat(idTokenJWSAlgs.contains(JWSAlgorithm.HS256)).isTrue();
        assertThat(idTokenJWSAlgs).hasSize(3);

        List<JWEAlgorithm> idTokenJWEAlgs = op.getIDTokenJWEAlgs();
        assertThat(idTokenJWEAlgs.contains(JWEAlgorithm.A128KW)).isTrue();
        assertThat(idTokenJWEAlgs).hasSize(1);

        List<EncryptionMethod> idTokenEncs = op.getIDTokenJWEEncs();
        assertThat(idTokenEncs.contains(EncryptionMethod.A128CBC_HS256)).isTrue();
        assertThat(idTokenEncs.contains(EncryptionMethod.A128GCM)).isTrue();
        assertThat(idTokenEncs).hasSize(2);

        // Request object
        List<JWSAlgorithm> requestObjectJWSAlgs = op.getRequestObjectJWSAlgs();
        assertThat(requestObjectJWSAlgs.contains(JWSAlgorithm.NONE)).isTrue();
        assertThat(requestObjectJWSAlgs.contains(JWSAlgorithm.RS256)).isTrue();
        assertThat(requestObjectJWSAlgs.contains(JWSAlgorithm.ES256)).isTrue();

        List<Display> displayTypes = op.getDisplays();
        assertThat(displayTypes.contains(Display.PAGE)).isTrue();
        assertThat(displayTypes.contains(Display.POPUP)).isTrue();
        assertThat(displayTypes).hasSize(2);

        List<ClaimType> claimTypes = op.getClaimTypes();
        assertThat(claimTypes.contains(ClaimType.NORMAL)).isTrue();
        assertThat(claimTypes.contains(ClaimType.DISTRIBUTED)).isTrue();
        assertThat(claimTypes).hasSize(2);

        List<String> claims = op.getClaims();
        assertThat(claims.contains("sub")).isTrue();
        assertThat(claims.contains("iss")).isTrue();
        assertThat(claims.contains("auth_time")).isTrue();
        assertThat(claims.contains("acr")).isTrue();
        assertThat(claims.contains("name")).isTrue();
        assertThat(claims.contains("given_name")).isTrue();
        assertThat(claims.contains("family_name")).isTrue();
        assertThat(claims.contains("nickname")).isTrue();
        assertThat(claims.contains("profile")).isTrue();
        assertThat(claims.contains("picture")).isTrue();
        assertThat(claims.contains("website")).isTrue();
        assertThat(claims.contains("email")).isTrue();
        assertThat(claims.contains("email_verified")).isTrue();
        assertThat(claims.contains("locale")).isTrue();
        assertThat(claims.contains("zoneinfo")).isTrue();
        assertThat(claims.contains("http://example.info/claims/groups")).isTrue();
        assertThat(claims).hasSize(16);

        assertThat(op.supportsClaimsParam()).isTrue();

        assertThat(op.getServiceDocsURI().toString()).isEqualTo("http://server.example.com/connect/service_documentation.html");

        // logout channels
        assertThat(op.supportsFrontChannelLogout()).isFalse();
        assertThat(op.supportsFrontChannelLogoutSession()).isFalse();
        assertThat(op.supportsBackChannelLogout()).isFalse();
        assertThat(op.supportsBackChannelLogoutSession()).isFalse();

        assertThat(op.getMtlsEndpointAliases()).isNull();
        assertThat(op.supportsTLSClientCertificateBoundAccessTokens()).isFalse();
        assertThat(op.supportsMutualTLSSenderConstrainedAccessTokens()).isFalse();

        assertThat(op.getAuthorizationJWSAlgs()).isNull();
        assertThat(op.getAuthorizationJWEAlgs()).isNull();
        assertThat(op.getAuthorizationJWEEncs()).isNull();

        assertThat(op.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testGettersAndSetters()
            throws Exception {

        Issuer issuer = new Issuer("https://c2id.com");

        List<SubjectType> subjectTypes = new LinkedList<>();
        subjectTypes.add(SubjectType.PAIRWISE);
        subjectTypes.add(SubjectType.PUBLIC);

        URI jwkSetURI = new URI("https://c2id.com/jwks.json");

        OIDCProviderMetadata meta = new OIDCProviderMetadata(issuer, subjectTypes, jwkSetURI);

        assertThat(meta.getIssuer().getValue()).isEqualTo(issuer.getValue());
        assertThat(meta.getSubjectTypes().get(0)).isEqualTo(SubjectType.PAIRWISE);
        assertThat(meta.getSubjectTypes().get(1)).isEqualTo(SubjectType.PUBLIC);
        assertThat(meta.getJWKSetURI().toString()).isEqualTo(jwkSetURI.toString());

        meta.setAuthorizationEndpointURI(new URI("https://c2id.com/authz"));
        assertThat(meta.getAuthorizationEndpointURI().toString()).isEqualTo("https://c2id.com/authz");

        meta.setTokenEndpointURI(new URI("https://c2id.com/token"));
        assertThat(meta.getTokenEndpointURI().toString()).isEqualTo("https://c2id.com/token");

        meta.setUserInfoEndpointURI(new URI("https://c2id.com/userinfo"));
        assertThat(meta.getUserInfoEndpointURI().toString()).isEqualTo("https://c2id.com/userinfo");

        meta.setRegistrationEndpointURI(new URI("https://c2id.com/reg"));
        assertThat(meta.getRegistrationEndpointURI().toString()).isEqualTo("https://c2id.com/reg");

        meta.setIntrospectionEndpointURI(new URI("https://c2id.com/inspect"));
        assertThat(meta.getIntrospectionEndpointURI().toString()).isEqualTo("https://c2id.com/inspect");

        meta.setRevocationEndpointURI(new URI("https://c2id.com/revoke"));
        assertThat(meta.getRevocationEndpointURI().toString()).isEqualTo("https://c2id.com/revoke");

        meta.setCheckSessionIframeURI(new URI("https://c2id.com/session"));
        assertThat(meta.getCheckSessionIframeURI().toString()).isEqualTo("https://c2id.com/session");

        meta.setEndSessionEndpointURI(new URI("https://c2id.com/logout"));
        assertThat(meta.getEndSessionEndpointURI().toString()).isEqualTo("https://c2id.com/logout");

        meta.setScopes(Scope.parse("openid email profile"));
        assertThat(Scope.parse("openid email profile").containsAll(meta.getScopes())).isTrue();

        List<ResponseType> responseTypes = new LinkedList<>();
        ResponseType rt1 = new ResponseType();
        rt1.add(ResponseType.Value.CODE);
        responseTypes.add(rt1);
        meta.setResponseTypes(responseTypes);
        responseTypes = meta.getResponseTypes();
        assertThat(responseTypes.iterator().next().iterator().next()).isEqualTo(ResponseType.Value.CODE);
        assertThat(responseTypes).hasSize(1);

        List<ResponseMode> responseModes = new LinkedList<>();
        responseModes.add(ResponseMode.QUERY);
        responseModes.add(ResponseMode.FRAGMENT);
        meta.setResponseModes(responseModes);
        assertThat(meta.getResponseModes().contains(ResponseMode.QUERY)).isTrue();
        assertThat(meta.getResponseModes().contains(ResponseMode.FRAGMENT)).isTrue();
        assertThat(meta.getResponseModes()).hasSize(2);

        List<GrantType> grantTypes = new LinkedList<>();
        grantTypes.add(GrantType.AUTHORIZATION_CODE);
        grantTypes.add(GrantType.REFRESH_TOKEN);
        meta.setGrantTypes(grantTypes);
        assertThat(meta.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE)).isTrue();
        assertThat(meta.getGrantTypes().contains(GrantType.REFRESH_TOKEN)).isTrue();
        assertThat(meta.getGrantTypes()).hasSize(2);

        List<CodeChallengeMethod> codeChallengeMethods = Arrays.asList(CodeChallengeMethod.S256, CodeChallengeMethod.S256);
        meta.setCodeChallengeMethods(codeChallengeMethods);
        assertThat(meta.getCodeChallengeMethods()).isEqualTo(codeChallengeMethods);

        List<ACR> acrList = new LinkedList<>();
        acrList.add(new ACR("1"));
        meta.setACRs(acrList);
        assertThat(meta.getACRs().get(0).getValue()).isEqualTo("1");

        meta.setTokenEndpointAuthMethods(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
        assertThat(meta.getTokenEndpointAuthMethods()).isEqualTo(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));

        meta.setTokenEndpointJWSAlgs(Arrays.asList(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512));
        assertThat(meta.getTokenEndpointJWSAlgs()).isEqualTo(Arrays.asList(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512));

        meta.setIntrospectionEndpointAuthMethods(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_POST));
        assertThat(meta.getIntrospectionEndpointAuthMethods()).isEqualTo(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_POST));

        meta.setIntrospectionEndpointJWSAlgs(Collections.singletonList(JWSAlgorithm.HS256));
        assertThat(meta.getIntrospectionEndpointJWSAlgs()).isEqualTo(Collections.singletonList(JWSAlgorithm.HS256));

        meta.setRevocationEndpointAuthMethods(Collections.singletonList(ClientAuthenticationMethod.PRIVATE_KEY_JWT));
        assertThat(meta.getRevocationEndpointAuthMethods()).isEqualTo(Collections.singletonList(ClientAuthenticationMethod.PRIVATE_KEY_JWT));

        meta.setRevocationEndpointJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
        assertThat(meta.getRevocationEndpointJWSAlgs()).isEqualTo(Collections.singletonList(JWSAlgorithm.RS256));

        meta.setRequestObjectEndpoint(new URI("https://c2id.com/requests"));
        assertThat(meta.getRequestObjectEndpoint()).isEqualTo(new URI("https://c2id.com/requests"));

        List<JWSAlgorithm> requestObjectJWSAlgs = new LinkedList<>();
        requestObjectJWSAlgs.add(JWSAlgorithm.HS256);
        meta.setRequestObjectJWSAlgs(requestObjectJWSAlgs);
        assertThat(meta.getRequestObjectJWSAlgs().get(0)).isEqualTo(JWSAlgorithm.HS256);

        List<JWEAlgorithm> requestObjectJWEAlgs = new LinkedList<>();
        requestObjectJWEAlgs.add(JWEAlgorithm.A128KW);
        meta.setRequestObjectJWEAlgs(requestObjectJWEAlgs);
        assertThat(meta.getRequestObjectJWEAlgs().get(0)).isEqualTo(JWEAlgorithm.A128KW);

        List<EncryptionMethod> requestObjectEncs = new LinkedList<>();
        requestObjectEncs.add(EncryptionMethod.A128GCM);
        meta.setRequestObjectJWEEncs(requestObjectEncs);
        assertThat(meta.getRequestObjectJWEEncs().get(0)).isEqualTo(EncryptionMethod.A128GCM);

        List<JWSAlgorithm> idTokenJWSAlgs = new LinkedList<>();
        idTokenJWSAlgs.add(JWSAlgorithm.RS256);
        meta.setIDTokenJWSAlgs(idTokenJWSAlgs);
        assertThat(meta.getIDTokenJWSAlgs().get(0)).isEqualTo(JWSAlgorithm.RS256);

        List<JWEAlgorithm> idTokenJWEalgs = new LinkedList<>();
        idTokenJWEalgs.add(JWEAlgorithm.A256KW);
        meta.setIDTokenJWEAlgs(idTokenJWEalgs);

        List<EncryptionMethod> idTokenEncs = new LinkedList<>();
        idTokenEncs.add(EncryptionMethod.A128GCM);
        meta.setIDTokenJWEEncs(idTokenEncs);
        assertThat(meta.getIDTokenJWEEncs().get(0)).isEqualTo(EncryptionMethod.A128GCM);

        List<JWSAlgorithm> userInfoJWSAlgs = new LinkedList<>();
        userInfoJWSAlgs.add(JWSAlgorithm.RS256);
        meta.setUserInfoJWSAlgs(userInfoJWSAlgs);
        assertThat(meta.getUserInfoJWSAlgs().get(0)).isEqualTo(JWSAlgorithm.RS256);

        List<JWEAlgorithm> userInfoJWEAlgs = new LinkedList<>();
        userInfoJWEAlgs.add(JWEAlgorithm.RSA_OAEP_256);
        meta.setUserInfoJWEAlgs(userInfoJWEAlgs);
        assertThat(meta.getUserInfoJWEAlgs().get(0)).isEqualTo(JWEAlgorithm.RSA_OAEP_256);

        List<EncryptionMethod> userInfoEncs = new LinkedList<>();
        userInfoEncs.add(EncryptionMethod.A128CBC_HS256);
        meta.setUserInfoJWEEncs(userInfoEncs);
        assertThat(meta.getUserInfoJWEEncs().get(0)).isEqualTo(EncryptionMethod.A128CBC_HS256);

        List<Display> displays = new LinkedList<>();
        displays.add(Display.PAGE);
        displays.add(Display.POPUP);
        meta.setDisplays(displays);
        assertThat(meta.getDisplays().get(0)).isEqualTo(Display.PAGE);
        assertThat(meta.getDisplays().get(1)).isEqualTo(Display.POPUP);
        assertThat(meta.getDisplays()).hasSize(2);

        List<ClaimType> claimTypes = new LinkedList<>();
        claimTypes.add(ClaimType.NORMAL);
        meta.setClaimTypes(claimTypes);
        assertThat(meta.getClaimTypes().get(0)).isEqualTo(ClaimType.NORMAL);

        List<String> claims = new LinkedList<>();
        claims.add("name");
        claims.add("email");
        meta.setClaims(claims);
        assertThat(meta.getClaims().get(0)).isEqualTo("name");
        assertThat(meta.getClaims().get(1)).isEqualTo("email");
        assertThat(meta.getClaims()).hasSize(2);

        meta.setServiceDocsURI(new URI("https://c2id.com/docs"));
        assertThat(meta.getServiceDocsURI().toString()).isEqualTo("https://c2id.com/docs");

        meta.setPolicyURI(new URI("https://c2id.com/policy"));
        assertThat(meta.getPolicyURI().toString()).isEqualTo("https://c2id.com/policy");

        meta.setTermsOfServiceURI(new URI("https://c2id.com/tos"));
        assertThat(meta.getTermsOfServiceURI().toString()).isEqualTo("https://c2id.com/tos");

        meta.setSupportsClaimsParams(true);
        assertThat(meta.supportsClaimsParam()).isTrue();

        meta.setSupportsRequestParam(true);
        assertThat(meta.supportsRequestParam()).isTrue();

        meta.setSupportsRequestURIParam(true);
        assertThat(meta.supportsRequestURIParam()).isTrue();

        meta.setRequiresRequestURIRegistration(true);
        assertThat(meta.requiresRequestURIRegistration()).isTrue();

        assertThat(meta.supportsFrontChannelLogout()).isFalse();
        meta.setSupportsFrontChannelLogout(true);
        assertThat(meta.supportsFrontChannelLogout()).isTrue();

        assertThat(meta.supportsFrontChannelLogoutSession()).isFalse();
        meta.setSupportsFrontChannelLogoutSession(true);
        assertThat(meta.supportsFrontChannelLogoutSession()).isTrue();

        assertThat(meta.supportsBackChannelLogout()).isFalse();
        meta.setSupportsBackChannelLogout(true);
        assertThat(meta.supportsBackChannelLogout()).isTrue();

        assertThat(meta.supportsBackChannelLogoutSession()).isFalse();
        meta.setSupportsBackChannelLogoutSession(true);
        assertThat(meta.supportsBackChannelLogoutSession()).isTrue();

        AuthorizationServerEndpointMetadata asEndpoints = new AuthorizationServerEndpointMetadata();
        asEndpoints.setAuthorizationEndpointURI(meta.getAuthorizationEndpointURI());
        asEndpoints.setTokenEndpointURI(meta.getTokenEndpointURI());
        asEndpoints.setRegistrationEndpointURI(meta.getRegistrationEndpointURI());
        asEndpoints.setIntrospectionEndpointURI(meta.getIntrospectionEndpointURI());
        asEndpoints.setRevocationEndpointURI(meta.getRevocationEndpointURI());
        asEndpoints.setDeviceAuthorizationEndpointURI(meta.getDeviceAuthorizationEndpointURI());
        asEndpoints.setRequestObjectEndpoint(meta.getRequestObjectEndpoint());
        assertThat(meta.getMtlsEndpointAliases()).isNull();

        meta.setMtlsEndpointAliases(asEndpoints);
        assertThat(meta.getMtlsEndpointAliases()).isInstanceOf(OIDCProviderEndpointMetadata.class);
        assertThat(meta.getAuthorizationEndpointURI()).isEqualTo(meta.getMtlsEndpointAliases().getAuthorizationEndpointURI());
        assertThat(meta.getTokenEndpointURI()).isEqualTo(meta.getMtlsEndpointAliases().getTokenEndpointURI());
        assertThat(meta.getRegistrationEndpointURI()).isEqualTo(meta.getMtlsEndpointAliases().getRegistrationEndpointURI());
        assertThat(meta.getIntrospectionEndpointURI()).isEqualTo(meta.getMtlsEndpointAliases().getIntrospectionEndpointURI());
        assertThat(meta.getRevocationEndpointURI()).isEqualTo(meta.getMtlsEndpointAliases().getRevocationEndpointURI());
        assertThat(meta.getDeviceAuthorizationEndpointURI()).isEqualTo(meta.getMtlsEndpointAliases().getDeviceAuthorizationEndpointURI());
        assertThat(meta.getRequestObjectEndpoint()).isEqualTo(meta.getMtlsEndpointAliases().getRequestObjectEndpoint());
        assertThat(meta.getMtlsEndpointAliases().getUserInfoEndpointURI()).isNull();

        meta.getMtlsEndpointAliases().setUserInfoEndpointURI(meta.getUserInfoEndpointURI());
        assertThat(meta.getUserInfoEndpointURI()).isEqualTo(meta.getMtlsEndpointAliases().getUserInfoEndpointURI());

        assertThat(meta.supportsTLSClientCertificateBoundAccessTokens()).isFalse();
        assertThat(meta.supportsMutualTLSSenderConstrainedAccessTokens()).isFalse();
        meta.setSupportsTLSClientCertificateBoundAccessTokens(true);
        meta.setSupportsMutualTLSSenderConstrainedAccessTokens(true);
        assertThat(meta.supportsTLSClientCertificateBoundAccessTokens()).isTrue();
        assertThat(meta.supportsMutualTLSSenderConstrainedAccessTokens()).isTrue();

        List<JWSAlgorithm> authzJWSAlgs = Collections.singletonList(JWSAlgorithm.ES256);
        meta.setAuthorizationJWSAlgs(authzJWSAlgs);
        assertThat(meta.getAuthorizationJWSAlgs()).isEqualTo(authzJWSAlgs);

        List<JWEAlgorithm> authzJWEAlgs = Collections.singletonList(JWEAlgorithm.ECDH_ES);
        meta.setAuthorizationJWEAlgs(authzJWEAlgs);
        assertThat(meta.getAuthorizationJWEAlgs()).isEqualTo(authzJWEAlgs);

        List<EncryptionMethod> authzJWEEncs = Collections.singletonList(EncryptionMethod.A256GCM);
        meta.setAuthorizationJWEEncs(authzJWEEncs);
        assertThat(meta.getAuthorizationJWEEncs()).isEqualTo(authzJWEEncs);

        meta.setCustomParameter("x-custom", "xyz");

        assertThat(meta.getCustomParameters()).hasSize(1);
        assertThat(meta.getCustomParameter("x-custom")).isEqualTo("xyz");

        String json = meta.toJSONObject().build().toString();

        meta = OIDCProviderMetadata.parse(json);

        assertThat(meta.getIssuer().getValue()).isEqualTo(issuer.getValue());
        assertThat(meta.getSubjectTypes().get(0)).isEqualTo(SubjectType.PAIRWISE);
        assertThat(meta.getSubjectTypes().get(1)).isEqualTo(SubjectType.PUBLIC);
        assertThat(meta.getJWKSetURI().toString()).isEqualTo(jwkSetURI.toString());

        assertThat(meta.getAuthorizationEndpointURI().toString()).isEqualTo("https://c2id.com/authz");
        assertThat(meta.getTokenEndpointURI().toString()).isEqualTo("https://c2id.com/token");
        assertThat(meta.getUserInfoEndpointURI().toString()).isEqualTo("https://c2id.com/userinfo");
        assertThat(meta.getRegistrationEndpointURI().toString()).isEqualTo("https://c2id.com/reg");
        assertThat(meta.getIntrospectionEndpointURI().toString()).isEqualTo("https://c2id.com/inspect");
        assertThat(meta.getRevocationEndpointURI().toString()).isEqualTo("https://c2id.com/revoke");
        assertThat(meta.getCheckSessionIframeURI().toString()).isEqualTo("https://c2id.com/session");
        assertThat(meta.getEndSessionEndpointURI().toString()).isEqualTo("https://c2id.com/logout");

        assertThat(Scope.parse("openid email profile").containsAll(meta.getScopes())).isTrue();

        assertThat(responseTypes.iterator().next().iterator().next()).isEqualTo(ResponseType.Value.CODE);
        assertThat(responseTypes).hasSize(1);

        assertThat(meta.getResponseModes().contains(ResponseMode.QUERY)).isTrue();
        assertThat(meta.getResponseModes().contains(ResponseMode.FRAGMENT)).isTrue();
        assertThat(meta.getResponseModes()).hasSize(2);

        assertThat(meta.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE)).isTrue();
        assertThat(meta.getGrantTypes().contains(GrantType.REFRESH_TOKEN)).isTrue();
        assertThat(meta.getGrantTypes()).hasSize(2);

        assertThat(meta.getCodeChallengeMethods()).isEqualTo(codeChallengeMethods);

        assertThat(meta.getACRs().get(0).getValue()).isEqualTo("1");

        assertThat(meta.getTokenEndpointAuthMethods()).isEqualTo(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));

        assertThat(meta.getTokenEndpointAuthMethods()).isEqualTo(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
        assertThat(meta.getTokenEndpointJWSAlgs()).isEqualTo(Arrays.asList(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512));

        assertThat(meta.getIntrospectionEndpointAuthMethods()).isEqualTo(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_POST));
        assertThat(meta.getIntrospectionEndpointJWSAlgs()).isEqualTo(Collections.singletonList(JWSAlgorithm.HS256));

        assertThat(meta.getRevocationEndpointAuthMethods()).isEqualTo(Collections.singletonList(ClientAuthenticationMethod.PRIVATE_KEY_JWT));
        assertThat(meta.getRevocationEndpointJWSAlgs()).isEqualTo(Collections.singletonList(JWSAlgorithm.RS256));

        assertThat(meta.getRequestObjectEndpoint()).isEqualTo(new URI("https://c2id.com/requests"));

        assertThat(meta.getRequestObjectJWSAlgs().get(0)).isEqualTo(JWSAlgorithm.HS256);

        assertThat(meta.getRequestObjectJWEAlgs().get(0)).isEqualTo(JWEAlgorithm.A128KW);

        assertThat(meta.getRequestObjectJWEEncs().get(0)).isEqualTo(EncryptionMethod.A128GCM);

        assertThat(meta.getIDTokenJWSAlgs().get(0)).isEqualTo(JWSAlgorithm.RS256);

        assertThat(meta.getIDTokenJWEEncs().get(0)).isEqualTo(EncryptionMethod.A128GCM);

        assertThat(meta.getUserInfoJWSAlgs().get(0)).isEqualTo(JWSAlgorithm.RS256);

        assertThat(meta.getUserInfoJWEAlgs().get(0)).isEqualTo(JWEAlgorithm.RSA_OAEP_256);

        assertThat(meta.getUserInfoJWEEncs().get(0)).isEqualTo(EncryptionMethod.A128CBC_HS256);

        assertThat(meta.getDisplays().get(0)).isEqualTo(Display.PAGE);
        assertThat(meta.getDisplays().get(1)).isEqualTo(Display.POPUP);
        assertThat(meta.getDisplays()).hasSize(2);

        assertThat(meta.getClaimTypes().get(0)).isEqualTo(ClaimType.NORMAL);

        assertThat(meta.getClaims().get(0)).isEqualTo("name");
        assertThat(meta.getClaims().get(1)).isEqualTo("email");
        assertThat(meta.getClaims()).hasSize(2);

        assertThat(meta.getServiceDocsURI().toString()).isEqualTo("https://c2id.com/docs");

        assertThat(meta.getPolicyURI().toString()).isEqualTo("https://c2id.com/policy");

        assertThat(meta.getTermsOfServiceURI().toString()).isEqualTo("https://c2id.com/tos");

        assertThat(meta.supportsClaimsParam()).isTrue();

        assertThat(meta.supportsRequestParam()).isTrue();

        assertThat(meta.supportsRequestURIParam()).isTrue();

        assertThat(meta.requiresRequestURIRegistration()).isTrue();

        assertThat(meta.supportsFrontChannelLogout()).isTrue();
        assertThat(meta.supportsFrontChannelLogoutSession()).isTrue();
        assertThat(meta.supportsBackChannelLogout()).isTrue();
        assertThat(meta.supportsBackChannelLogoutSession()).isTrue();

        assertThat(meta.supportsTLSClientCertificateBoundAccessTokens()).isTrue();

        assertThat(meta.getAuthorizationJWSAlgs()).isEqualTo(authzJWSAlgs);
        assertThat(meta.getAuthorizationJWEAlgs()).isEqualTo(authzJWEAlgs);
        assertThat(meta.getAuthorizationJWEEncs()).isEqualTo(authzJWEEncs);

        assertThat(meta.getCustomParameters()).hasSize(1);
        assertThat(meta.getCustomParameter("x-custom")).isEqualTo("xyz");
    }

    @Test
    public void testRejectNoneAlgForTokenJWTAuth()
            throws Exception {

        Issuer issuer = new Issuer("https://c2id.com");

        List<SubjectType> subjectTypes = new ArrayList<>();
        subjectTypes.add(SubjectType.PUBLIC);

        URI jwksURI = new URI("https://c2id.com/jwks.json");

        OIDCProviderMetadata meta = new OIDCProviderMetadata(issuer, subjectTypes, jwksURI);

        List<JWSAlgorithm> tokenEndpointJWTAlgs = new ArrayList<>();
        tokenEndpointJWTAlgs.add(new JWSAlgorithm("none"));

        Assertions.assertThrows(IllegalArgumentException.class, () ->
                meta.setTokenEndpointJWSAlgs(tokenEndpointJWTAlgs));


        // Simulate JSON object with none token endpoint JWT algs
        JsonObjectBuilder jsonObjectBuilder = meta.toJSONObject();

        List<String> stringList = new ArrayList<>();
        stringList.add("none");

        jsonObjectBuilder.add("token_endpoint_auth_signing_alg_values_supported", JSONObjectUtils.asJsonArray(stringList));


        Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                OIDCProviderMetadata.parse(jsonObjectBuilder.build().toString()));

    }

    @Test
    public void testApplyDefaults()
            throws Exception {

        Issuer issuer = new Issuer("https://c2id.com");

        List<SubjectType> subjectTypes = new ArrayList<>();
        subjectTypes.add(SubjectType.PUBLIC);

        URI jwksURI = new URI("https://c2id.com/jwks.json");

        OIDCProviderMetadata meta = new OIDCProviderMetadata(issuer, subjectTypes, jwksURI);

        meta.applyDefaults();

        List<ResponseMode> responseModes = meta.getResponseModes();
        assertThat(responseModes.contains(ResponseMode.QUERY)).isTrue();
        assertThat(responseModes.contains(ResponseMode.FRAGMENT)).isTrue();
        assertThat(responseModes).hasSize(2);

        List<GrantType> grantTypes = meta.getGrantTypes();
        assertThat(grantTypes.contains(GrantType.AUTHORIZATION_CODE)).isTrue();
        assertThat(grantTypes.contains(GrantType.IMPLICIT)).isTrue();
        assertThat(grantTypes).hasSize(2);

        assertThat(meta.getTokenEndpointAuthMethods()).isEqualTo(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));

        List<ClaimType> claimTypes = meta.getClaimTypes();
        assertThat(claimTypes.contains(ClaimType.NORMAL)).isTrue();
        assertThat(claimTypes).hasSize(1);
    }

    @Test
    public void testWithCustomParameters()
            throws Exception {

        Issuer issuer = new Issuer("https://c2id.com");

        List<SubjectType> subjectTypes = new ArrayList<>();
        subjectTypes.add(SubjectType.PUBLIC);

        URI jwksURI = new URI("https://c2id.com/jwks.json");

        OIDCProviderMetadata meta = new OIDCProviderMetadata(issuer, subjectTypes, jwksURI);

        meta.applyDefaults();

        assertThat(meta.getCustomParameters().isEmpty()).isTrue();

        meta = new OIDCProviderMetadata(issuer, subjectTypes, jwksURI);
        meta.setCustomParameter("token_introspection_endpoint", "https://c2id.com/token/introspect");
        meta.setCustomParameter("token_revocation_endpoint", "https://c2id.com/token/revoke");

        assertThat(meta.getCustomParameter("token_introspection_endpoint")).isEqualTo("https://c2id.com/token/introspect");
        assertThat(meta.getCustomParameter("token_revocation_endpoint")).isEqualTo("https://c2id.com/token/revoke");
        assertThat(meta.getCustomURIParameter("token_introspection_endpoint")).isEqualTo(URI.create("https://c2id.com/token/introspect"));
        assertThat(meta.getCustomURIParameter("token_revocation_endpoint")).isEqualTo(URI.create("https://c2id.com/token/revoke"));

        assertThat(meta.getCustomParameters().getString("token_introspection_endpoint")).isEqualTo("https://c2id.com/token/introspect");
        assertThat(meta.getCustomParameters().getString("token_revocation_endpoint")).isEqualTo("https://c2id.com/token/revoke");
        assertThat(meta.getCustomParameters()).hasSize(2);

        JsonObject o = meta.toJSONObject().build();

        meta = OIDCProviderMetadata.parse(o);

        assertThat(meta.getCustomParameter("token_introspection_endpoint")).isEqualTo("https://c2id.com/token/introspect");
        assertThat(meta.getCustomParameter("token_revocation_endpoint")).isEqualTo("https://c2id.com/token/revoke");
        assertThat(meta.getCustomURIParameter("token_introspection_endpoint")).isEqualTo(URI.create("https://c2id.com/token/introspect"));
        assertThat(meta.getCustomURIParameter("token_revocation_endpoint")).isEqualTo(URI.create("https://c2id.com/token/revoke"));

        assertThat(meta.getCustomParameters().getString("token_introspection_endpoint")).isEqualTo("https://c2id.com/token/introspect");
        assertThat(meta.getCustomParameters().getString("token_revocation_endpoint")).isEqualTo("https://c2id.com/token/revoke");
        assertThat(meta.getCustomParameters()).hasSize(2);
    }

    @Test
    public void testParseNullValues() throws OAuth2JSONParseException {

        JsonObjectBuilder jsonObjectbuilder = Json.createObjectBuilder();

        for (String paramName : OIDCClientMetadata.getRegisteredParameterNames()) {
            jsonObjectbuilder.addNull(paramName);
        }

        // Mandatory
        jsonObjectbuilder.add("issuer", "https://c2id.com");
        jsonObjectbuilder.add("subject_types_supported", JSONObjectUtils.asJsonArray(Arrays.asList("public", "pairwise")));
        jsonObjectbuilder.add("jwks_uri", "https://c2id.com/jwks.json");

        OIDCProviderMetadata.parse(jsonObjectbuilder.build());
    }

    @Test
    public void testPreserveTokenEndpointJWSAlgsParseOrder()
            throws Exception {

        JsonObjectBuilder jsonObjectbuilder = Json.createObjectBuilder();
        jsonObjectbuilder.add("issuer", "https://c2id.com");
        jsonObjectbuilder.add("subject_types_supported", JSONObjectUtils.asJsonArray(Arrays.asList("public", "pairwise")));
        jsonObjectbuilder.add("jwks_uri", "https://c2id.com/jwks.json");
        jsonObjectbuilder.add("token_endpoint_auth_signing_alg_values_supported", JSONObjectUtils.asJsonArray(Arrays.asList("RS256", "PS256", "HS256", "ES256")));

        OIDCProviderMetadata opMetadata = OIDCProviderMetadata.parse(jsonObjectbuilder.build().toString());

        assertThat(opMetadata.getTokenEndpointJWSAlgs().get(0)).isEqualTo(JWSAlgorithm.RS256);
        assertThat(opMetadata.getTokenEndpointJWSAlgs().get(1)).isEqualTo(JWSAlgorithm.PS256);
        assertThat(opMetadata.getTokenEndpointJWSAlgs().get(2)).isEqualTo(JWSAlgorithm.HS256);
        assertThat(opMetadata.getTokenEndpointJWSAlgs().get(3)).isEqualTo(JWSAlgorithm.ES256);
        assertThat(opMetadata.getTokenEndpointJWSAlgs()).hasSize(4);
    }


    // iss 212
    @Test
    public void testJOSEAlgParse_referenceEquality()
            throws Exception {

        JsonObjectBuilder jsonObjectbuilder = Json.createObjectBuilder();
        jsonObjectbuilder.add("issuer", "https://c2id.com");
        jsonObjectbuilder.add("subject_types_supported", JSONObjectUtils.asJsonArray(Arrays.asList("public", "pairwise")));
        jsonObjectbuilder.add("jwks_uri", "https://c2id.com/jwks.json");

        jsonObjectbuilder.add("token_endpoint_auth_signing_alg_values_supported", JSONObjectUtils.asJsonArray(Collections.singletonList("RS256")));

        jsonObjectbuilder.add("request_object_signing_alg_values_supported", JSONObjectUtils.asJsonArray(Collections.singletonList("RS256")));
        jsonObjectbuilder.add("request_object_encryption_alg_values_supported", JSONObjectUtils.asJsonArray(Collections.singletonList("RSA-OAEP-256")));
        jsonObjectbuilder.add("request_object_encryption_enc_values_supported", JSONObjectUtils.asJsonArray(Collections.singletonList("A128GCM")));

        jsonObjectbuilder.add("id_token_signing_alg_values_supported", JSONObjectUtils.asJsonArray(Collections.singletonList("RS256")));
        jsonObjectbuilder.add("id_token_encryption_alg_values_supported", JSONObjectUtils.asJsonArray(Collections.singletonList("RSA-OAEP-256")));
        jsonObjectbuilder.add("id_token_encryption_enc_values_supported", JSONObjectUtils.asJsonArray(Collections.singletonList("A128GCM")));

        jsonObjectbuilder.add("userinfo_signing_alg_values_supported", JSONObjectUtils.asJsonArray(Collections.singletonList("RS256")));
        jsonObjectbuilder.add("userinfo_encryption_alg_values_supported", JSONObjectUtils.asJsonArray(Collections.singletonList("RSA-OAEP-256")));
        jsonObjectbuilder.add("userinfo_encryption_enc_values_supported", JSONObjectUtils.asJsonArray(Collections.singletonList("A128GCM")));

        OIDCProviderMetadata opMetadata = OIDCProviderMetadata.parse(jsonObjectbuilder.build().toString());

        assertThat(opMetadata.getTokenEndpointJWSAlgs().get(0)).isEqualTo(JWSAlgorithm.RS256);

        assertThat(opMetadata.getRequestObjectJWSAlgs().get(0)).isEqualTo(JWSAlgorithm.RS256);
        assertThat(opMetadata.getRequestObjectJWEAlgs().get(0)).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(opMetadata.getRequestObjectJWEEncs().get(0)).isEqualTo(EncryptionMethod.A128GCM);


        assertThat(opMetadata.getIDTokenJWSAlgs().get(0)).isEqualTo(JWSAlgorithm.RS256);
        assertThat(opMetadata.getIDTokenJWEAlgs().get(0)).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(opMetadata.getIDTokenJWEEncs().get(0)).isEqualTo(EncryptionMethod.A128GCM);

        assertThat(opMetadata.getUserInfoJWSAlgs().get(0)).isEqualTo(JWSAlgorithm.RS256);
        assertThat(opMetadata.getUserInfoJWEAlgs().get(0)).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(opMetadata.getUserInfoJWEEncs().get(0)).isEqualTo(EncryptionMethod.A128GCM);
    }

    @Test
    public void testOutputFrontChannelLogoutSessionSupported() {

        OIDCProviderMetadata meta = new OIDCProviderMetadata(
                new Issuer("https://c2id.com"),
                Collections.singletonList(SubjectType.PUBLIC),
                URI.create("https://c2id.com/jwks.json"));

        meta.applyDefaults();

        JsonObject out = meta.toJSONObject().build();
        assertThat(out.getBoolean("frontchannel_logout_supported")).isFalse();
        assertThat(out.containsKey("frontchannel_logout_session_supported")).isFalse();

        meta.setSupportsFrontChannelLogout(true);
        out = meta.toJSONObject().build();
        assertThat(out.getBoolean("frontchannel_logout_supported")).isTrue();
        assertThat(out.getBoolean("frontchannel_logout_session_supported")).isFalse();

        meta.setSupportsFrontChannelLogoutSession(true);
        out = meta.toJSONObject().build();
        assertThat(out.getBoolean("frontchannel_logout_supported")).isTrue();
        assertThat(out.getBoolean("frontchannel_logout_session_supported")).isTrue();
    }

    @Test
    public void testOutputBackChannelLogoutSessionSupported() {

        OIDCProviderMetadata meta = new OIDCProviderMetadata(
                new Issuer("https://c2id.com"),
                Collections.singletonList(SubjectType.PUBLIC),
                URI.create("https://c2id.com/jwks.json"));

        meta.applyDefaults();

        JsonObject out = meta.toJSONObject().build();
        assertThat(out.getBoolean("backchannel_logout_supported")).isFalse();
        assertThat(out.containsKey("backchannel_logout_session_supported")).isFalse();

        meta.setSupportsBackChannelLogout(true);
        out = meta.toJSONObject().build();
        assertThat(out.getBoolean("backchannel_logout_supported")).isTrue();
        assertThat(out.getBoolean("backchannel_logout_session_supported")).isFalse();

        meta.setSupportsBackChannelLogoutSession(true);
        out = meta.toJSONObject().build();
        assertThat(out.getBoolean("backchannel_logout_supported")).isTrue();
        assertThat(out.getBoolean("backchannel_logout_session_supported")).isTrue();
    }

    @Test
    public void testParseDefaultFrontAndBackChannelLogoutSupport()
            throws OAuth2JSONParseException {

        OIDCProviderMetadata meta = new OIDCProviderMetadata(
                new Issuer("https://c2id.com"),
                Collections.singletonList(SubjectType.PUBLIC),
                URI.create("https://c2id.com/jwks.json"));

        meta.applyDefaults();

        JsonObject out = meta.toJSONObject().build();

        // default - not set
        assertThat(JSONObjectUtils.hasValue(out, "frontchannel_logout_supported")).isTrue();
        assertThat(JSONObjectUtils.hasValue(out, "frontchannel_logout_session_supported")).isFalse();
        assertThat(JSONObjectUtils.hasValue(out, "backchannel_logout_supported")).isTrue();
        assertThat(JSONObjectUtils.hasValue(out, "backchannel_logout_session_supported")).isFalse();

        JsonObjectBuilder outBuilder = Json.createObjectBuilder(out);
        outBuilder.remove("frontchannel_logout_supported");
        outBuilder.remove("frontchannel_logout_session_supported");
        outBuilder.remove("backchannel_logout_supported");
        outBuilder.remove("backchannel_logout_session_supported");
        out = outBuilder.build();

        meta = OIDCProviderMetadata.parse(out.toString());

        assertThat(meta.supportsFrontChannelLogout()).isFalse();
        assertThat(meta.supportsFrontChannelLogoutSession()).isFalse();
        assertThat(meta.supportsBackChannelLogout()).isFalse();
        assertThat(meta.supportsBackChannelLogoutSession()).isFalse();
    }

    @Test
    public void testParseBasicFrontAndBackChannelLogoutSupport()
            throws OAuth2JSONParseException {

        OIDCProviderMetadata meta = new OIDCProviderMetadata(
                new Issuer("https://c2id.com"),
                Collections.singletonList(SubjectType.PUBLIC),
                URI.create("https://c2id.com/jwks.json"));

        meta.applyDefaults();
        meta.setSupportsFrontChannelLogout(true);
        meta.setSupportsBackChannelLogout(true);

        JsonObject out = meta.toJSONObject().build();

        // Optional session supported flag defaults to false
        assertThat(out.containsKey("frontchannel_logout_session_supported")).isTrue();
        assertThat(out.containsKey("backchannel_logout_session_supported")).isTrue();

        JsonObjectBuilder outBuilder = Json.createObjectBuilder(out);
        outBuilder.remove("frontchannel_logout_session_supported");
        outBuilder.remove("backchannel_logout_session_supported");

        meta = OIDCProviderMetadata.parse(outBuilder.build().toString());

        assertThat(meta.supportsFrontChannelLogout()).isTrue();
        assertThat(meta.supportsFrontChannelLogoutSession()).isFalse();
        assertThat(meta.supportsBackChannelLogout()).isTrue();
        assertThat(meta.supportsBackChannelLogoutSession()).isFalse();
    }

    @Test
    public void testOutputTLSClientCertificateBoundAccessTokensSupport()
            throws OAuth2JSONParseException {

        OIDCProviderMetadata meta = new OIDCProviderMetadata(
                new Issuer("https://c2id.com"),
                Collections.singletonList(SubjectType.PUBLIC),
                URI.create("https://c2id.com/jwks.json"));

        meta.applyDefaults();


        JsonObject jsonObject = meta.toJSONObject().build();

        assertThat(jsonObject.getBoolean("tls_client_certificate_bound_access_tokens")).isFalse();

        assertThat(OIDCProviderMetadata.parse(jsonObject).supportsTLSClientCertificateBoundAccessTokens()).isFalse();

        // default to false
        assertThat(jsonObject.containsKey("tls_client_certificate_bound_access_tokens")).isTrue();
        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder(jsonObject);
        jsonObjectBuilder.remove("tls_client_certificate_bound_access_tokens");

        assertThat(OIDCProviderMetadata.parse(jsonObject).supportsTLSClientCertificateBoundAccessTokens()).isFalse();

        meta.setSupportsTLSClientCertificateBoundAccessTokens(true);

        jsonObjectBuilder = meta.toJSONObject();
        jsonObject = jsonObjectBuilder.build();

        assertThat(jsonObject.getBoolean("tls_client_certificate_bound_access_tokens")).isTrue();

        assertThat(OIDCProviderMetadata.parse(jsonObject).supportsTLSClientCertificateBoundAccessTokens()).isTrue();
    }
}