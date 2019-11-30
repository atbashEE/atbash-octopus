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
package be.atbash.ee.openid.connect.sdk.op;


import be.atbash.ee.oauth2.sdk.*;
import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.openid.connect.sdk.AuthenticationRequest;
import be.atbash.ee.openid.connect.sdk.ClaimsRequest;
import be.atbash.ee.openid.connect.sdk.Nonce;
import be.atbash.ee.openid.connect.sdk.SubjectType;
import be.atbash.ee.openid.connect.sdk.claims.ACR;
import be.atbash.ee.openid.connect.sdk.claims.ClaimRequirement;
import be.atbash.ee.openid.connect.sdk.rp.OIDCClientInformation;
import be.atbash.ee.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.Test;

import java.net.URI;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the ACR request class.
 */
public class ACRRequestTest {

    @Test
    public void testConstructAndGet() {

        List<ACR> essentialACRs = new ArrayList<>();
        essentialACRs.add(new ACR("1"));

        List<ACR> voluntaryACRs = new ArrayList<>();
        voluntaryACRs.add(new ACR("2"));

        ACRRequest req = new ACRRequest(essentialACRs, voluntaryACRs);

        assertThat(req.getEssentialACRs()).isEqualTo(essentialACRs);
        assertThat(req.getVoluntaryACRs()).isEqualTo(voluntaryACRs);

        assertThat(req.getEssentialACRs()).hasSize(1);
        assertThat(req.getVoluntaryACRs()).hasSize(1);
    }

    @Test
    public void testConstructAndGetNull() {

        ACRRequest req = new ACRRequest(null, null);

        assertThat(req.getEssentialACRs()).isNull();
        assertThat(req.getVoluntaryACRs()).isNull();
    }

    @Test
    public void testResolvePlainOAuthRequest()
            throws Exception {

        AuthorizationRequest authzRequest = new AuthorizationRequest(
                new URI("https://c2id.com/login"),
                new ResponseType("token"),
                new ClientID("abc"));

        ACRRequest acrRequest = ACRRequest.resolve(authzRequest);

        assertThat(acrRequest.getEssentialACRs()).isNull();
        assertThat(acrRequest.getVoluntaryACRs()).isNull();

        assertThat(acrRequest.isEmpty()).isTrue();
    }

    @Test
    public void testResolveNone()
            throws Exception {

        AuthenticationRequest authRequest = new AuthenticationRequest(
                new URI("https://c2id.com/login"),
                new ResponseType("code"),
                Scope.parse("openid profile"),
                new ClientID("abc"),
                new URI("https://example.com/in"),
                new State(),
                new Nonce());

        ACRRequest acrRequest = ACRRequest.resolve(authRequest);

        assertThat(acrRequest.getEssentialACRs()).isNull();
        assertThat(acrRequest.getVoluntaryACRs()).isNull();

        assertThat(acrRequest.isEmpty()).isTrue();
    }

    @Test
    public void testResolveTopLevelACRRequest()
            throws Exception {

        List<ACR> acrValues = new ArrayList<>();
        acrValues.add(new ACR("1"));
        acrValues.add(new ACR("2"));

        AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid", "profile"),
                new ClientID("123"),
                new URI("https://example.com/in")).
                acrValues(acrValues).
                build();

        ACRRequest acrRequest = ACRRequest.resolve(authRequest);

        assertThat(acrRequest.getEssentialACRs()).isNull();

        List<ACR> voluntaryACRs = acrRequest.getVoluntaryACRs();

        assertThat(voluntaryACRs.contains(new ACR("1"))).isTrue();
        assertThat(voluntaryACRs.contains(new ACR("2"))).isTrue();

        assertThat(voluntaryACRs).hasSize(2);

        assertThat(acrRequest.isEmpty()).isFalse();
    }

    @Test
    public void testResolveClaimsLevelEssentialACRRequest()
            throws Exception {

        ClaimsRequest claims = new ClaimsRequest();

        List<String> essentialACRs = new ArrayList<>();
        essentialACRs.add("A");
        essentialACRs.add("B");
        claims.addIDTokenClaim("acr", ClaimRequirement.ESSENTIAL, essentialACRs);

        AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid", "profile"),
                new ClientID("123"),
                new URI("https://example.com/in")).
                claims(claims).
                build();

        ACRRequest acrRequest = ACRRequest.resolve(authRequest);

        assertThat(acrRequest.getEssentialACRs().contains(new ACR("A"))).isTrue();
        assertThat(acrRequest.getEssentialACRs().contains(new ACR("B"))).isTrue();
        assertThat(acrRequest.getEssentialACRs()).hasSize(2);

        assertThat(acrRequest.getVoluntaryACRs()).isNull();

        assertThat(acrRequest.isEmpty()).isFalse();
    }

    @Test
    public void testResolveClaimsLevelVoluntaryACRRequest()
            throws Exception {

        ClaimsRequest claims = new ClaimsRequest();

        List<String> essentialACRs = new ArrayList<>();
        essentialACRs.add("A");
        essentialACRs.add("B");
        claims.addIDTokenClaim("acr", ClaimRequirement.VOLUNTARY, essentialACRs);

        AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid", "profile"),
                new ClientID("123"),
                new URI("https://example.com/in")).
                claims(claims).
                build();

        ACRRequest acrRequest = ACRRequest.resolve(authRequest);

        assertThat(acrRequest.getEssentialACRs()).isNull();

        assertThat(acrRequest.getVoluntaryACRs().contains(new ACR("A"))).isTrue();
        assertThat(acrRequest.getVoluntaryACRs().contains(new ACR("B"))).isTrue();
        assertThat(acrRequest.getVoluntaryACRs()).hasSize(2);

        assertThat(acrRequest.isEmpty()).isFalse();
    }

    @Test
    public void testResolveMixedACRRequest()
            throws Exception {

        List<ACR> acrValues = new ArrayList<>();
        acrValues.add(new ACR("1"));
        acrValues.add(new ACR("2"));

        ClaimsRequest claims = new ClaimsRequest();

        List<String> essentialACRs = new ArrayList<>();
        essentialACRs.add("A");
        essentialACRs.add("B");
        claims.addIDTokenClaim("acr", ClaimRequirement.ESSENTIAL, essentialACRs);

        AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid", "profile"),
                new ClientID("123"),
                new URI("https://example.com/in")).
                acrValues(acrValues).
                claims(claims).
                build();

        ACRRequest acrRequest = ACRRequest.resolve(authRequest);

        assertThat(acrRequest.getEssentialACRs().contains(new ACR("A"))).isTrue();
        assertThat(acrRequest.getEssentialACRs().contains(new ACR("B"))).isTrue();
        assertThat(acrRequest.getEssentialACRs()).hasSize(2);

        assertThat(acrRequest.getVoluntaryACRs().contains(new ACR("1"))).isTrue();
        assertThat(acrRequest.getVoluntaryACRs().contains(new ACR("2"))).isTrue();
        assertThat(acrRequest.getVoluntaryACRs()).hasSize(2);

        assertThat(acrRequest.isEmpty()).isFalse();
    }

    @Test
    public void testApplyDefaultACR_nothingToApply() {

        ACRRequest acrRequest = new ACRRequest(null, null);

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
        clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
        clientMetadata.applyDefaults();
        OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), clientMetadata, new Secret());

        acrRequest = acrRequest.applyDefaultACRs(clientInfo);

        assertThat(acrRequest.isEmpty()).isTrue();
    }

    @Test
    public void testApplyDefaultACR_explicitACRs_essential() {

        ACRRequest acrRequest = new ACRRequest(Collections.singletonList(new ACR("1")), null);

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
        clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
        clientMetadata.applyDefaults();
        OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), clientMetadata, new Secret());

        acrRequest = acrRequest.applyDefaultACRs(clientInfo);

        assertThat(acrRequest.getEssentialACRs().get(0)).isEqualTo(new ACR("1"));
        assertThat(acrRequest.getEssentialACRs()).hasSize(1);

        assertThat(acrRequest.getVoluntaryACRs()).isNull();

        assertThat(acrRequest.isEmpty()).isFalse();
    }

    @Test
    public void testApplyDefaultACR_explicitACRs_voluntary() {

        ACRRequest acrRequest = new ACRRequest(null, Collections.singletonList(new ACR("1")));

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
        clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
        clientMetadata.applyDefaults();
        OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), clientMetadata, new Secret());

        acrRequest = acrRequest.applyDefaultACRs(clientInfo);

        assertThat(acrRequest.getEssentialACRs()).isNull();

        assertThat(acrRequest.getVoluntaryACRs().get(0)).isEqualTo(new ACR("1"));
        assertThat(acrRequest.getVoluntaryACRs()).hasSize(1);

        assertThat(acrRequest.isEmpty()).isFalse();
    }

    @Test
    public void testApplyDefaultACR_applyRegisteredACRValue() {

        ACRRequest acrRequest = new ACRRequest(null, null);

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
        clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
        clientMetadata.setDefaultACRs(Collections.singletonList(new ACR("1")));
        clientMetadata.applyDefaults();
        OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), clientMetadata, new Secret());

        acrRequest = acrRequest.applyDefaultACRs(clientInfo);

        assertThat(acrRequest.getEssentialACRs()).isNull();

        assertThat(acrRequest.getVoluntaryACRs().get(0)).isEqualTo(new ACR("1"));
        assertThat(acrRequest.getVoluntaryACRs()).hasSize(1);

        assertThat(acrRequest.isEmpty()).isFalse();
    }

    @Test
    public void testApplyDefaultACR_applyRegisteredACRValuesMultiple() {

        ACRRequest acrRequest = new ACRRequest(null, null);

        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
        clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
        clientMetadata.setDefaultACRs(Arrays.asList(new ACR("1"), new ACR("2")));
        clientMetadata.applyDefaults();
        OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), clientMetadata, new Secret());

        acrRequest = acrRequest.applyDefaultACRs(clientInfo);

        assertThat(acrRequest.getEssentialACRs()).isNull();

        assertThat(acrRequest.getVoluntaryACRs().get(0)).isEqualTo(new ACR("1"));
        assertThat(acrRequest.getVoluntaryACRs().get(1)).isEqualTo(new ACR("2"));
        assertThat(acrRequest.getVoluntaryACRs()).hasSize(2);

        assertThat(acrRequest.isEmpty()).isFalse();
    }

    @Test
    public void testEnsureACRSupport_noEssentialACRsRequested()
            throws GeneralException {

        AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("https://example.com/cb"))
                .build();

        ACRRequest acrRequest = ACRRequest.resolve(authRequest);

        OIDCProviderMetadata opMetadata = new OIDCProviderMetadata(
                new Issuer("https://c2id.com"),
                Arrays.asList(SubjectType.PUBLIC, SubjectType.PAIRWISE),
                URI.create("https://c2id.com/jwks.json"));
        opMetadata.applyDefaults();

        acrRequest.ensureACRSupport(authRequest, opMetadata);

        acrRequest.ensureACRSupport(authRequest, opMetadata.getACRs());
    }

    @Test
    public void testEnsureACRSupport_noEssentialACRsSupported() {

        ClaimsRequest claimsRequest = new ClaimsRequest();
        claimsRequest.addIDTokenClaim("acr", ClaimRequirement.ESSENTIAL, "1");

        AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("https://example.com/cb"))
                .claims(claimsRequest)
                .build();

        ACRRequest acrRequest = ACRRequest.resolve(authRequest);

        OIDCProviderMetadata opMetadata = new OIDCProviderMetadata(
                new Issuer("https://c2id.com"),
                Arrays.asList(SubjectType.PUBLIC, SubjectType.PAIRWISE),
                URI.create("https://c2id.com/jwks.json"));
        opMetadata.applyDefaults();

        try {
            acrRequest.ensureACRSupport(authRequest, opMetadata);
        } catch (GeneralException e) {
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.ACCESS_DENIED);
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Access denied by resource owner or authorization server: Requested essential ACR(s) not supported");
            assertThat(e.getMessage()).isEqualTo("Requested essential ACR(s) not supported");
        }

        try {
            acrRequest.ensureACRSupport(authRequest, opMetadata.getACRs());
        } catch (GeneralException e) {
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.ACCESS_DENIED);
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Access denied by resource owner or authorization server: Requested essential ACR(s) not supported");
            assertThat(e.getMessage()).isEqualTo("Requested essential ACR(s) not supported");
        }
    }

    @Test
    public void testEnsureACRSupport_essentialACRsSupported() {

        ClaimsRequest claimsRequest = new ClaimsRequest();
        claimsRequest.addIDTokenClaim("acr", ClaimRequirement.ESSENTIAL, "1");

        AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("https://example.com/cb"))
                .claims(claimsRequest)
                .build();

        ACRRequest acrRequest = ACRRequest.resolve(authRequest);

        OIDCProviderMetadata opMetadata = new OIDCProviderMetadata(
                new Issuer("https://c2id.com"),
                Arrays.asList(SubjectType.PUBLIC, SubjectType.PAIRWISE),
                URI.create("https://c2id.com/jwks.json"));
        opMetadata.setACRs(Collections.singletonList(new ACR("1")));
        opMetadata.applyDefaults();

        try {
            acrRequest.ensureACRSupport(authRequest, opMetadata);
        } catch (GeneralException e) {
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.ACCESS_DENIED);
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Access denied by resource owner or authorization server: Requested essential ACR(s) not supported");
            assertThat(e.getMessage()).isEqualTo("Requested essential ACR(s) not supported");
        }

        try {
            acrRequest.ensureACRSupport(authRequest, opMetadata.getACRs());
        } catch (GeneralException e) {
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.ACCESS_DENIED);
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Access denied by resource owner or authorization server: Requested essential ACR(s) not supported");
            assertThat(e.getMessage()).isEqualTo("Requested essential ACR(s) not supported");
        }
    }
}