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
package be.atbash.ee.security.octopus.sso.client.requestor;

import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.sso.client.OpenIdVariableClientData;
import be.atbash.ee.security.octopus.sso.client.config.OctopusSSOServerClientConfiguration;
import be.atbash.ee.security.octopus.sso.core.OctopusRetrievalException;
import be.atbash.ee.security.octopus.sso.core.rest.PrincipalUserInfoJSONProvider;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOTokenConverter;
import be.atbash.ee.security.octopus.util.SecretUtil;
import be.atbash.util.TestReflectionUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.jadler.Jadler;
import net.minidev.json.JSONObject;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class OctopusUserRequestorTest {

    private static final String APPLICATION_JWT = "application/jwt";

    @Mock
    private OctopusSSOServerClientConfiguration octopusSSOServerClientConfigurationMock;

    @Mock
    private OctopusCoreConfiguration octopusCoreConfigurationMock;

    @Mock
    private OctopusSSOTokenConverter octopusSSOTokenConverterMock;

    @Mock
    private PrincipalUserInfoJSONProvider userInfoJSONProviderMock;

    @InjectMocks
    private OctopusUserRequestor octopusUserRequestor;

    @Before
    public void setUp() throws IllegalAccessException {
        Jadler.initJadler();

        TestReflectionUtils.injectDependencies(octopusUserRequestor, new OctopusSSOTokenConverter());

        octopusUserRequestor.setConfiguration(octopusCoreConfigurationMock, octopusSSOServerClientConfigurationMock);
    }

    @After
    public void tearDown() {
        Jadler.closeJadler();
    }

    @Test
    public void getOctopusSSOToken() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("JUnit");
        builder.issuer("http://localhost/oidc");
        builder.audience("JUnit_client");
        builder.claim("nonce", clientData.getNonce().getValue());
        builder.expirationTime(addSecondsToDate(2, new Date()));

        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String secret = secretUtil.generateSecretBase64(32);

        when(octopusSSOServerClientConfigurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(octopusSSOServerClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost/oidc");
        when(octopusSSOServerClientConfigurationMock.getSSOClientId()).thenReturn("JUnit_client");
        when(octopusSSOServerClientConfigurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, builder.build());

        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }
        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(signedJWT.serialize())
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        OctopusSSOToken ssoToken = octopusUserRequestor.getOctopusSSOToken(clientData, accessToken);

        assertThat(ssoToken.getAccessToken()).isEqualTo(accessToken.getValue());
        assertThat(ssoToken.getUserInfo()).hasSize(5);
    }

    @Test(expected = OctopusRetrievalException.class)
    public void getOctopusSSOToken_expired() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("JUnit");
        builder.issuer("http://localhost/oidc");
        builder.audience("JUnit_client");
        builder.claim("nonce", clientData.getNonce().getValue());
        builder.expirationTime(new Date());

        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String secret = secretUtil.generateSecretBase64(32);

        when(octopusSSOServerClientConfigurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(octopusSSOServerClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost/oidc");
        when(octopusSSOServerClientConfigurationMock.getSSOClientId()).thenReturn("JUnit_client");
        when(octopusSSOServerClientConfigurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, builder.build());

        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }
        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(signedJWT.serialize())
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        OctopusSSOToken ssoToken = octopusUserRequestor.getOctopusSSOToken(clientData, accessToken);

        assertThat(ssoToken.getAccessToken()).isEqualTo(accessToken.getValue());
        assertThat(ssoToken.getUserInfo()).hasSize(5);
    }

    @Test(expected = OctopusRetrievalException.class)
    public void getOctopusSSOToken_invalidSignature() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("JUnit");
        builder.issuer("http://localhost/oidc");
        builder.audience("JUnit_client");
        builder.claim("nonce", clientData.getNonce().getValue());
        builder.expirationTime(new Date());

        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String secret = secretUtil.generateSecretBase64(32);

        when(octopusSSOServerClientConfigurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(octopusSSOServerClientConfigurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, builder.build());

        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }
        StringBuilder jwtString = new StringBuilder(signedJWT.serialize());
        jwtString.deleteCharAt(jwtString.length() - 10);  // By removing a character, we make the sign invalid

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(jwtString.toString())
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        OctopusSSOToken ssoToken = octopusUserRequestor.getOctopusSSOToken(clientData, accessToken);

        assertThat(ssoToken.getAccessToken()).isEqualTo(accessToken.getValue());
        assertThat(ssoToken.getUserInfo()).hasSize(5);
    }

    @Test(expected = OctopusRetrievalException.class)
    public void getOctopusSSOToken_missingNonce() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("JUnit");
        builder.issuer("http://localhost/oidc");
        builder.audience("JUnit_client");
        builder.expirationTime(addSecondsToDate(2, new Date()));

        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String secret = secretUtil.generateSecretBase64(32);

        when(octopusSSOServerClientConfigurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(octopusSSOServerClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost/oidc");
        when(octopusSSOServerClientConfigurationMock.getSSOClientId()).thenReturn("JUnit_client");
        when(octopusSSOServerClientConfigurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, builder.build());

        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }
        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(signedJWT.serialize())
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        octopusUserRequestor.getOctopusSSOToken(clientData, accessToken);

    }

    @Test
    public void getOctopusSSOToken_missingAud() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("JUnit");
        builder.issuer("http://localhost/oidc");
        builder.audience("JUnit_client");
        builder.claim("nonce", clientData.getNonce().getValue());
        builder.expirationTime(addSecondsToDate(2, new Date()));

        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String secret = secretUtil.generateSecretBase64(32);

        when(octopusSSOServerClientConfigurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(octopusSSOServerClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost/oidc");
        when(octopusSSOServerClientConfigurationMock.getSSOClientId()).thenReturn("anotherClient");
        when(octopusSSOServerClientConfigurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, builder.build());

        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }
        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(signedJWT.serialize())
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        try {
            octopusUserRequestor.getOctopusSSOToken(clientData, accessToken);
            Assert.fail("Exception expected");
        } catch (OctopusRetrievalException e) {
            assertThat(e.getMessage()).isEqualTo("JWT claim Validation failed : aud");
        }

    }

    @Test
    public void getOctopusSSOToken_customValidator() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException, IllegalAccessException {
        // Inject custom validator
        CustomUserInfoValidator customUserInfoValidatorMock = Mockito.mock(CustomUserInfoValidator.class);
        TestReflectionUtils.injectDependencies(octopusUserRequestor, customUserInfoValidatorMock);

        // Change List of Claims
        List<String> wrongClaims = new ArrayList<String>();
        wrongClaims.add("JUnit");
        when(customUserInfoValidatorMock.validateUserInfo(any(UserInfo.class), any(OpenIdVariableClientData.class), ArgumentMatchers.<String>anyList()))
                .thenReturn(wrongClaims);

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject("JUnit");
        builder.issuer("http://localhost/oidc");
        builder.audience("JUnit_client");
        builder.claim("nonce", clientData.getNonce().getValue());
        builder.expirationTime(addSecondsToDate(2, new Date()));

        SecretUtil secretUtil = new SecretUtil();
        secretUtil.init();
        String secret = secretUtil.generateSecretBase64(32);

        when(octopusSSOServerClientConfigurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(octopusSSOServerClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost/oidc");
        when(octopusSSOServerClientConfigurationMock.getSSOClientId()).thenReturn("anotherClient");
        when(octopusSSOServerClientConfigurationMock.getSSOIdTokenSecret()).thenReturn(secret.getBytes());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, builder.build());

        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }
        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(signedJWT.serialize())
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        try {
            octopusUserRequestor.getOctopusSSOToken(clientData, accessToken);
            Assert.fail("Exception expected");
        } catch (OctopusRetrievalException e) {
            assertThat(e.getMessage()).isEqualTo("JWT claim Validation failed : JUnit");
        }

    }

    @Test(expected = OctopusRetrievalException.class)
    public void getOctopusSSOToken_ErrorReturn() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");

        when(octopusSSOServerClientConfigurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");

        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withStatus(400)
                .withBody("{}")
                .withContentType(APPLICATION_JWT);


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        octopusUserRequestor.getOctopusSSOToken(clientData, accessToken);


    }

    @Test
    public void getOctopusSSOToken_plainJSONResult() throws ParseException, JOSEException, OctopusRetrievalException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {

        OpenIdVariableClientData clientData = new OpenIdVariableClientData();

        when(octopusSSOServerClientConfigurationMock.getUserInfoEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/user");
        when(octopusSSOServerClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost/oidc");

        JSONObject json = new JSONObject();
        json.put("sub", "JUnit");
        json.put("iss", "http://localhost/oidc");
        json.put("exp", addSecondsToDate(2, new Date()).getTime());


        Jadler.onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/oidc/octopus/sso/user")
                .havingHeaderEqualTo("Authorization", "Bearer TheAccessToken")
                .respond()
                .withBody(json.toJSONString())
                .withContentType("application/json");


        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");

        OctopusSSOToken ssoToken = octopusUserRequestor.getOctopusSSOToken(clientData, accessToken);

        assertThat(ssoToken.getAccessToken()).isEqualTo(accessToken.getValue());
        assertThat(ssoToken.getUserInfo()).hasSize(3);
        assertThat(ssoToken.getUserInfo()).containsKeys("sub", "iss", "exp");
    }

    private static Date addSecondsToDate(long seconds, Date beforeTime) {

        long curTimeInMs = beforeTime.getTime();
        return new Date(curTimeInMs + (seconds * 1000));
    }

}