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
package be.atbash.ee.security.sso.server.authz;

import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.openid.connect.sdk.LogoutRequest;
import be.atbash.ee.openid.connect.sdk.claims.IDTokenClaimsSet;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.TimeUtil;
import be.atbash.ee.security.sso.server.client.ClientInfo;
import be.atbash.ee.security.sso.server.client.ClientInfoRetriever;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class SSOLogoutFilterTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private ClientInfoRetriever clientInfoRetrieverMock;

    @Mock
    private SSOTokenStore tokenStoreMock;

    @Mock
    private UserPrincipal userPrincipalMock;

    @Mock
    private WebSubject webSubjectMock;

    @InjectMocks
    private SSOLogoutFilter filter;

    @AfterEach
    public void teardown() {
        TestLoggerFactory.clear();
    }

    @Test
    public void isAccessAllowed_webScenario() throws Exception {
        // With Cookie so SecurityUtils.getSubject need to return an authenticated Subject.

        TestLogger logger = TestLoggerFactory.getTestLogger(SSOLogoutFilter.class);

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getPrincipal()).thenReturn(userPrincipalMock);

        byte[] secret = defineSecret(256 / 8 + 1);
        String clientId = "clientId";

        when(httpServletRequestMock.getQueryString()).thenReturn(createQueryString(clientId, secret, clientId, "http://some.server/logout"));

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setClientSecret(Base64.getUrlEncoder().withoutPadding().encodeToString(secret));
        clientInfo.setOctopusClient(true);
        when(clientInfoRetrieverMock.retrieveInfo("clientId")).thenReturn(clientInfo);


        boolean accessAllowed = filter.isAccessAllowed(httpServletRequestMock, httpServletResponseMock);
        assertThat(accessAllowed).isTrue();

        assertThat(logger.getLoggingEvents()).isEmpty();
        verifyNoMoreInteractions(tokenStoreMock);  // So that we are sure no .login() attempt is performed
    }


    @Test
    public void isAccessAllowed_seScenario() throws Exception {
        // With Cookie so SecurityUtils.getSubject need to return null.

        TestLogger logger = TestLoggerFactory.getTestLogger(SSOLogoutFilter.class);

        ThreadContext.bind(webSubjectMock);

        byte[] secret = defineSecret(256 / 8 + 1);
        String clientId = "clientId";

        when(httpServletRequestMock.getQueryString()).thenReturn(createQueryString(clientId, secret, "theAccessCode", "http://some.server/logout"));

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setClientSecret(Base64.getUrlEncoder().withoutPadding().encodeToString(secret));
        clientInfo.setOctopusClient(true);
        when(clientInfoRetrieverMock.retrieveInfo("clientId")).thenReturn(clientInfo);

        when(tokenStoreMock.getUserByAccessCode("theAccessCode")).thenReturn(userPrincipalMock);

        boolean accessAllowed = filter.isAccessAllowed(httpServletRequestMock, httpServletResponseMock);

        assertThat(accessAllowed).isTrue();

        assertThat(logger.getLoggingEvents()).isEmpty();
        verify(tokenStoreMock).getUserByAccessCode("theAccessCode");
        verify(webSubjectMock).login(any(AuthenticationToken.class));
    }

    @Test
    public void isAccessAllowed_unknownClientId() throws Exception {
        TestLogger logger = TestLoggerFactory.getTestLogger(SSOLogoutFilter.class);

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getPrincipal()).thenReturn(userPrincipalMock);

        byte[] secret = defineSecret(256 / 8 + 1);
        String clientId = "clientId";

        when(httpServletRequestMock.getQueryString()).thenReturn(createQueryString(clientId, secret, clientId, "http://some.server/logout"));

        when(clientInfoRetrieverMock.retrieveInfo("clientId")).thenReturn(null);


        boolean accessAllowed = filter.isAccessAllowed(httpServletRequestMock, httpServletResponseMock);
        assertThat(accessAllowed).isFalse();

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("SSOLogoutFilter: unknown clientId : clientId");

        verifyNoMoreInteractions(tokenStoreMock);  // So that we are sure no .login() attempt is performed
    }

    @Test
    public void isAccessAllowed_noRequestParameters() throws Exception {
        TestLogger logger = TestLoggerFactory.getTestLogger(SSOLogoutFilter.class);

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getPrincipal()).thenReturn(userPrincipalMock);

        when(httpServletRequestMock.getQueryString()).thenReturn("");

        boolean accessAllowed = filter.isAccessAllowed(httpServletRequestMock, httpServletResponseMock);
        assertThat(accessAllowed).isFalse();

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("SSOLogoutFilter: no query parameters found");

        verifyNoMoreInteractions(tokenStoreMock);  // So that we are sure no .login() attempt is performed
    }

    @Test
    public void isAccessAllowed_signatureVerificationIssue() throws Exception {
        TestLogger logger = TestLoggerFactory.getTestLogger(SSOLogoutFilter.class);

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getPrincipal()).thenReturn(userPrincipalMock);

        byte[] secret = defineSecret(256 / 8 + 1);
        String clientId = "clientId";

        when(httpServletRequestMock.getQueryString()).thenReturn(createQueryString(clientId, secret, clientId, "http://some.server/logout"));

        ClientInfo clientInfo = new ClientInfo();
        secret = defineSecret(256 / 8 + 1);  // another secret
        clientInfo.setClientSecret(Base64.getUrlEncoder().withoutPadding().encodeToString(secret));
        clientInfo.setOctopusClient(true);
        when(clientInfoRetrieverMock.retrieveInfo("clientId")).thenReturn(clientInfo);


        boolean accessAllowed = filter.isAccessAllowed(httpServletRequestMock, httpServletResponseMock);
        assertThat(accessAllowed).isFalse();

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).startsWith("SSOLogoutFilter: JWT Signing verification failed : ey");

        verifyNoMoreInteractions(tokenStoreMock);  // So that we are sure no .login() attempt is performed
    }

    @Test
    public void isAccessAllowed_timeOutExpirationDate() throws Exception {
        // With Cookie so SecurityUtils.getSubject need to return an authenticated Subject.

        TestLogger logger = TestLoggerFactory.getTestLogger(SSOLogoutFilter.class);

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getPrincipal()).thenReturn(userPrincipalMock);

        byte[] secret = defineSecret(256 / 8 + 1);
        String clientId = "clientId";

        when(httpServletRequestMock.getQueryString()).thenReturn(createQueryString(clientId, secret, clientId, "http://some.server/logout"));

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setClientSecret(Base64.getUrlEncoder().withoutPadding().encodeToString(secret));
        clientInfo.setOctopusClient(true);
        when(clientInfoRetrieverMock.retrieveInfo("clientId")).thenReturn(clientInfo);


        Thread.sleep(2100); // By default there is a sec timeToLive


        boolean accessAllowed = filter.isAccessAllowed(httpServletRequestMock, httpServletResponseMock);
        assertThat(accessAllowed).isFalse();

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).startsWith("SSOLogoutFilter: JWT expired : ey");

        verifyNoMoreInteractions(tokenStoreMock);  // So that we are sure no .login() attempt is performed
    }

    private String createQueryString(String clientId, byte[] secret, String subject, String logoutURL) {
        SignedJWT result;

        TimeUtil timeUtil = new TimeUtil();
        Date iat = new Date();
        Date exp = timeUtil.addSecondsToDate(2, iat);
        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(new Issuer(clientId), new Subject(subject), new ArrayList<>(), exp, iat);

        try {
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.HS256);
            headerBuilder.parameter("clientId", clientId);
            result = new SignedJWT(headerBuilder.build(), claimsSet.toJWTClaimsSet());

            result.sign(new MACSigner(secret));
        } catch (OAuth2JSONParseException | JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }

        URI redirectURI = null;
        if (logoutURL != null) {
            redirectURI = URI.create(logoutURL);
        }
        LogoutRequest logoutRequest = new LogoutRequest(null, result, redirectURI, null);
        return logoutRequest.toQueryString();

    }

    private byte[] defineSecret(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);

        return bytes;
    }

}