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
package be.atbash.ee.security.octopus.sso.callback;

import be.atbash.ee.oauth2.sdk.AuthorizationCode;
import be.atbash.ee.oauth2.sdk.ErrorObject;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.oauth2.sdk.token.AccessToken;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.openid.connect.sdk.OIDCTokenResponse;
import be.atbash.ee.openid.connect.sdk.claims.IDTokenClaimsSet;
import be.atbash.ee.openid.connect.sdk.token.OIDCTokens;
import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jwt.PlainJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.sso.client.JWSAlgorithmFactory;
import be.atbash.ee.security.octopus.sso.client.OpenIdVariableClientData;
import be.atbash.ee.security.octopus.sso.client.config.OctopusSSOServerClientConfiguration;
import net.jadler.Jadler;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class ExchangeForAccessCodeTest {

    @Mock
    private OctopusCoreConfiguration coreConfigurationMock;

    @Mock
    private OctopusSSOServerClientConfiguration octopusSSOServerClientConfigurationMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private CallbackErrorHandler callbackErrorHandlerMock;

    @Mock
    private JWSAlgorithmFactory jwsAlgorithmFactoryMock;

    @InjectMocks
    private ExchangeForAccessCode exchangeForAccessCode;

    @Captor
    private ArgumentCaptor<ErrorObject> errorObjectArgumentCaptor;

    @Before
    public void setUp() {
        Jadler.initJadler();
        when(coreConfigurationMock.showDebugFor()).thenReturn(Collections.<Debug>emptyList());
    }

    @After
    public void tearDown() {
        Jadler.closeJadler();
    }

    private void defineSecret(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);

        when(octopusSSOServerClientConfigurationMock.getSSOClientSecret()).thenReturn(bytes);

    }

    @Test
    public void doExchange_happyCase() throws OAuth2JSONParseException {
        defineSecret(256 / 8 + 1);
        when(jwsAlgorithmFactoryMock.determineOptimalAlgorithm(any(byte[].class))).thenReturn(JWSAlgorithm.HS256);
        exchangeForAccessCode.init();

        when(octopusSSOServerClientConfigurationMock.getTokenEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/token");
        when(octopusSSOServerClientConfigurationMock.getSSOClientId()).thenReturn("junit_client");

        OpenIdVariableClientData variableClientData = new OpenIdVariableClientData("http://some.server/oidc");
        AuthorizationCode authorizationCode = new AuthorizationCode("TheAuthorizationCode");

        OIDCTokens token = defineTokens(variableClientData, 2);
        OIDCTokenResponse oidcTokenResponse = new OIDCTokenResponse(token);

        when(octopusSSOServerClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://some.server/oidc");
        when(octopusSSOServerClientConfigurationMock.getSSOClientId()).thenReturn("junit_client");

        Jadler.onRequest()
                .havingPathEqualTo("/oidc/octopus/sso/token")
                .respond()
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody(oidcTokenResponse.toJSONObject().build().toString());

        BearerAccessToken accessToken = exchangeForAccessCode.doExchange(httpServletResponseMock, variableClientData, authorizationCode);

        assertThat(accessToken).isNotNull();
        assertThat(accessToken).isEqualTo(accessToken);

        StringBaseMatcher bodyMatcher = new StringBaseMatcher();
        Jadler.verifyThatRequest()
                .havingMethodEqualTo("POST")
                .havingBody(bodyMatcher)
                .receivedOnce();

        assertThat(bodyMatcher.getBody()).startsWith("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=TheAuthorizationCode&grant_type=authorization_code&redirect_uri=http%3A%2F%2Fsome.server%2Foidc%2Fsso%2FSSOCallback&client_assertion=eyJhbGciOiJIUzI1NiJ9.");

        verifyNoMoreInteractions(callbackErrorHandlerMock);
    }

    @Test
    public void doExchange_clientAuthenticationJWTExpired() throws OAuth2JSONParseException {
        defineSecret(256 / 8 + 1);
        when(jwsAlgorithmFactoryMock.determineOptimalAlgorithm(any(byte[].class))).thenReturn(JWSAlgorithm.HS256);
        exchangeForAccessCode.init();

        when(octopusSSOServerClientConfigurationMock.getTokenEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/token");
        when(octopusSSOServerClientConfigurationMock.getSSOClientId()).thenReturn("junit_client");

        OpenIdVariableClientData variableClientData = new OpenIdVariableClientData("http://some.server/oidc");
        AuthorizationCode authorizationCode = new AuthorizationCode("TheAuthorizationCode");

        OIDCTokens token = defineTokens(variableClientData, -1);
        OIDCTokenResponse oidcTokenResponse = new OIDCTokenResponse(token);

        when(octopusSSOServerClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://some.server/oidc");
        when(octopusSSOServerClientConfigurationMock.getSSOClientId()).thenReturn("junit_client");

        Jadler.onRequest()
                .havingPathEqualTo("/oidc/octopus/sso/token")
                .respond()
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody(oidcTokenResponse.toJSONObject().build().toString());

        BearerAccessToken accessToken = exchangeForAccessCode.doExchange(httpServletResponseMock, variableClientData, authorizationCode);

        assertThat(accessToken).isNull();

        StringBaseMatcher bodyMatcher = new StringBaseMatcher();
        Jadler.verifyThatRequest()
                .havingMethodEqualTo("POST")
                .havingBody(bodyMatcher)
                .receivedOnce();

        assertThat(bodyMatcher.getBody()).startsWith("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=TheAuthorizationCode&grant_type=authorization_code&redirect_uri=http%3A%2F%2Fsome.server%2Foidc%2Fsso%2FSSOCallback&client_assertion=eyJhbGciOiJIUzI1NiJ9.");

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());
        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("Validation of ID token JWT failed : Expired JWT");
    }

    @Test
    public void doExchange_clientAuthenticationJWTInvalidSigning() throws OAuth2JSONParseException, JOSEException {
        defineSecret(256 / 8 + 1);
        when(jwsAlgorithmFactoryMock.determineOptimalAlgorithm(any(byte[].class))).thenReturn(JWSAlgorithm.HS256);
        exchangeForAccessCode.init();

        when(octopusSSOServerClientConfigurationMock.getTokenEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/token");
        when(octopusSSOServerClientConfigurationMock.getSSOClientId()).thenReturn("junit_client");

        OpenIdVariableClientData variableClientData = new OpenIdVariableClientData("http://some.server/oidc");
        AuthorizationCode authorizationCode = new AuthorizationCode("TheAuthorizationCode");

        SecureRandom secureRandom = new SecureRandom();
        byte[] secret = new byte[32];
        secureRandom.nextBytes(secret);

        byte[] anotherSecret = new byte[32];
        secureRandom.nextBytes(anotherSecret); // Deliberately another secret so that validation fails.
        when(octopusSSOServerClientConfigurationMock.getSSOIdTokenSecret()).thenReturn(anotherSecret);

        OIDCTokens token = defineTokens(variableClientData, secret);
        OIDCTokenResponse oidcTokenResponse = new OIDCTokenResponse(token);

        when(octopusSSOServerClientConfigurationMock.getSSOClientId()).thenReturn("junit_client");

        Jadler.onRequest()
                .havingPathEqualTo("/oidc/octopus/sso/token")
                .respond()
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody(oidcTokenResponse.toJSONObject().build().toString());

        BearerAccessToken accessToken = exchangeForAccessCode.doExchange(httpServletResponseMock, variableClientData, authorizationCode);

        assertThat(accessToken).isNull();

        StringBaseMatcher bodyMatcher = new StringBaseMatcher();
        Jadler.verifyThatRequest()
                .havingMethodEqualTo("POST")
                .havingBody(bodyMatcher)
                .receivedOnce();

        assertThat(bodyMatcher.getBody()).startsWith("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=TheAuthorizationCode&grant_type=authorization_code&redirect_uri=http%3A%2F%2Fsome.server%2Foidc%2Fsso%2FSSOCallback&client_assertion=eyJhbGciOiJIUzI1NiJ9.");

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());
        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("JWT Signature Validation failed");
    }

    @Test
    public void doExchange_errorResponse() {
        defineSecret(256 / 8 + 1);
        when(jwsAlgorithmFactoryMock.determineOptimalAlgorithm(any(byte[].class))).thenReturn(JWSAlgorithm.HS256);
        exchangeForAccessCode.init();

        when(octopusSSOServerClientConfigurationMock.getTokenEndpoint()).thenReturn("http://localhost:" + Jadler.port() + "/oidc/octopus/sso/token");
        when(octopusSSOServerClientConfigurationMock.getSSOClientId()).thenReturn("junit_client");

        OpenIdVariableClientData variableClientData = new OpenIdVariableClientData("http://some.server/oidc");
        AuthorizationCode authorizationCode = new AuthorizationCode("TheAuthorizationCode");

        Jadler.onRequest()
                .havingPathEqualTo("/oidc/octopus/sso/token")
                .respond()
                .withStatus(HTTPResponse.SC_BAD_REQUEST)
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody("{\"error\":\"error code 1\",\"error_description\":\"some error description\"}");

        BearerAccessToken accessToken = exchangeForAccessCode.doExchange(httpServletResponseMock, variableClientData, authorizationCode);

        assertThat(accessToken).isNull();

        StringBaseMatcher bodyMatcher = new StringBaseMatcher();
        Jadler.verifyThatRequest()
                .havingMethodEqualTo("POST")
                .havingBody(bodyMatcher)
                .receivedOnce();

        assertThat(bodyMatcher.getBody()).startsWith("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=TheAuthorizationCode&grant_type=authorization_code&redirect_uri=http%3A%2F%2Fsome.server%2Foidc%2Fsso%2FSSOCallback&client_assertion=eyJhbGciOiJIUzI1NiJ9.");

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());
        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("some error description");
    }

    private OIDCTokens defineTokens(OpenIdVariableClientData variableClientData, int addSeconds) throws OAuth2JSONParseException {
        List<Audience> audiences = new ArrayList<>();
        audiences.add(new Audience("junit_client"));

        IDTokenClaimsSet idTokenClaimSet = new IDTokenClaimsSet(new Issuer("http://some.server/oidc"),
                new Subject("JUnit"), audiences, addSecondsToDate(addSeconds, new Date()), new Date());
        idTokenClaimSet.setNonce(variableClientData.getNonce());

        PlainJWT plainJWT = new PlainJWT(idTokenClaimSet.toJWTClaimsSet());

        AccessToken accessCode = new BearerAccessToken("TheAccessCode");

        return new OIDCTokens(plainJWT, accessCode, null);
    }

    private OIDCTokens defineTokens(OpenIdVariableClientData variableClientData, byte[] secret) throws OAuth2JSONParseException, JOSEException {

        List<Audience> audiences = new ArrayList<>();
        audiences.add(new Audience("junit_client"));

        IDTokenClaimsSet idTokenClaimSet = new IDTokenClaimsSet(new Issuer("http://some.server/oidc"),
                new Subject("JUnit"), audiences, addSecondsToDate(2, new Date()), new Date());
        idTokenClaimSet.setNonce(variableClientData.getNonce());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, idTokenClaimSet.toJWTClaimsSet());

        signedJWT.sign(new MACSigner(secret));

        AccessToken accessCode = new BearerAccessToken("TheAccessCode");

        return new OIDCTokens(signedJWT, accessCode, null);
    }

    private static Date addSecondsToDate(long seconds, Date beforeTime) {

        long curTimeInMs = beforeTime.getTime();
        return new Date(curTimeInMs + (seconds * 1000));
    }

    private class StringBaseMatcher extends BaseMatcher<String> {

        private String body;

        @Override
        public boolean matches(Object item) {
            body = item.toString();
            return true;
        }

        @Override
        public void describeTo(Description description) {

        }

        public String getBody() {
            return body;
        }
    }
}