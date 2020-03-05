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
package be.atbash.ee.security.sso.server.endpoint;

import be.atbash.ee.oauth2.sdk.AbstractRequest;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.ResponseType;
import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.id.*;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.openid.connect.sdk.AuthenticationRequest;
import be.atbash.ee.openid.connect.sdk.claims.IDTokenClaimsSet;
import be.atbash.ee.security.octopus.WebConstants;
import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.ee.security.octopus.keys.ListKeyManager;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACVerifier;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.sso.core.config.JARMLevel;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.TimeUtil;
import be.atbash.ee.security.sso.server.client.ClientInfo;
import be.atbash.ee.security.sso.server.config.OctopusSSOServerConfiguration;
import be.atbash.ee.security.sso.server.endpoint.helper.OIDCTokenHelper;
import be.atbash.ee.security.sso.server.store.OIDCStoreData;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.TestReflectionUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServletTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private OctopusSSOServerConfiguration ssoServerConfigurationMock;

    @Mock
    private AuthenticationRequest authenticationRequestMock;

    @Mock
    private SSOTokenStore tokenStoreMock;

    @Mock
    private HttpSession httpSessionMock;

    @Mock
    private OctopusCoreConfiguration octopusConfigMock;  // For the showDebugFor info

    @Mock
    private OIDCTokenHelper oidcTokenHelperMock;

    @Mock
    private WebSubject subjectMock;

    @Mock
    private JwtSupportConfiguration jwtSupportConfigurationMock;

    @Captor
    private ArgumentCaptor<String> stringArgumentCaptor;
    @Captor
    private ArgumentCaptor<String> cookieTokenArgumentCaptor;
    @Captor
    private ArgumentCaptor<String> userAgentArgumentCaptor;
    @Captor
    private ArgumentCaptor<String> remoteHostArgumentCaptor;

    @Captor
    private ArgumentCaptor<OIDCStoreData> oidcStoreDataArgumentCaptor;

    @InjectMocks
    private AuthenticationServlet authenticationServlet;

    private BeanManagerFake beanManagerFake;

    @BeforeEach
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(new TimeUtil(), TimeUtil.class);

        beanManagerFake.endRegistration();
    }

    @AfterEach
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void doGet_happyCase_CodeFlow() throws ServletException, IOException, OAuth2JSONParseException, URISyntaxException {
        when(ssoServerConfigurationMock.getJARMLevel()).thenReturn(JARMLevel.NONE);

        ThreadContext.bind(subjectMock);
        UserPrincipal userPrincipal = new UserPrincipal();
        when(subjectMock.getPrincipal()).thenReturn(userPrincipal);

        when(ssoServerConfigurationMock.getOIDCTokenLength()).thenReturn(48);
        when(ssoServerConfigurationMock.getSSOAccessTokenTimeToLive()).thenReturn(3600);

        when(httpServletRequestMock.getAttribute(AbstractRequest.class.getName())).thenReturn(authenticationRequestMock);
        when(authenticationRequestMock.getClientID()).thenReturn(new ClientID("JUnit_client"));
        when(authenticationRequestMock.getResponseType()).thenReturn(ResponseType.parse("code"));
        when(authenticationRequestMock.getRedirectionURI()).thenReturn(new URI("http://client.app/testing"));
        when(authenticationRequestMock.getState()).thenReturn(new State("stateValue"));
        when(authenticationRequestMock.getScope()).thenReturn(Scope.parse("scope1 scope2"));

        when(httpServletRequestMock.getSession()).thenReturn(httpSessionMock);

        userPrincipal.addUserInfo(WebConstants.SSO_COOKIE_TOKEN, "CookieTokenRememberMe");
        when(httpServletRequestMock.getHeader("User-Agent")).thenReturn("UserAgentValue");
        when(httpServletRequestMock.getRemoteAddr()).thenReturn("remoteAddressValue");

        List<Audience> aud = Audience.create("aud");
        IDTokenClaimsSet expectedClaimSet = new IDTokenClaimsSet(new Issuer("issuer"), new Subject("sub"), aud, new Date(), new Date());

        ClientID clientId = new ClientID("JUnit_client");
        when(oidcTokenHelperMock.defineIDToken(httpServletRequestMock, userPrincipal, clientId, authenticationRequestMock))
                .thenReturn(expectedClaimSet);

        authenticationServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());

        String callbackURL = stringArgumentCaptor.getValue();
        assertThat(callbackURL).startsWith("http://client.app/testing?code=");
        assertThat(callbackURL).endsWith("&state=stateValue");

        String authorizationCode = callbackURL.substring(31, callbackURL.indexOf('&'));
        byte[] bytes = new Base64URLValue(authorizationCode).decode();
        assertThat(bytes.length).isEqualTo(48);

        verify(tokenStoreMock).addLoginFromClient(any(UserPrincipal.class), cookieTokenArgumentCaptor.capture(),
                userAgentArgumentCaptor.capture(), remoteHostArgumentCaptor.capture(), oidcStoreDataArgumentCaptor.capture());

        assertThat(cookieTokenArgumentCaptor.getValue()).isEqualTo("CookieTokenRememberMe");
        assertThat(userAgentArgumentCaptor.getValue()).isEqualTo("UserAgentValue");
        assertThat(remoteHostArgumentCaptor.getValue()).isEqualTo("remoteAddressValue");

        assertThat(oidcStoreDataArgumentCaptor.getValue().getAuthorizationCode().getValue()).isEqualTo(authorizationCode);
        assertThat(oidcStoreDataArgumentCaptor.getValue().getAccessToken()).isNotNull();
        assertThat(oidcStoreDataArgumentCaptor.getValue().getScope().toStringList()).containsExactly("scope1", "scope2");
        assertThat(oidcStoreDataArgumentCaptor.getValue().getClientId().getValue()).isEqualTo("JUnit_client");

        IDTokenClaimsSet claimsSet = oidcStoreDataArgumentCaptor.getValue().getIdTokenClaimsSet();
        assertThat(claimsSet).isNotSameAs(expectedClaimSet);  // Since it is serialized/Deserialized

        verify(httpSessionMock).invalidate();
    }


    @Test
    public void doGet_happyCase_ImplicitFlow_IdTokenOnly() throws ServletException, IOException, OAuth2JSONParseException, URISyntaxException, java.text.ParseException {
        when(ssoServerConfigurationMock.getJARMLevel()).thenReturn(JARMLevel.NONE);

        ThreadContext.bind(subjectMock);
        UserPrincipal userPrincipal = new UserPrincipal();
        when(subjectMock.getPrincipal()).thenReturn(userPrincipal);

        when(ssoServerConfigurationMock.getOIDCTokenLength()).thenReturn(48);

        when(httpServletRequestMock.getAttribute(AbstractRequest.class.getName())).thenReturn(authenticationRequestMock);
        when(authenticationRequestMock.getResponseType()).thenReturn(ResponseType.parse("id_token"));
        when(authenticationRequestMock.getClientID()).thenReturn(new ClientID("JUnit_client"));
        when(authenticationRequestMock.getRedirectionURI()).thenReturn(new URI("http://client.app/testing"));
        when(authenticationRequestMock.getState()).thenReturn(new State("stateValue"));
        when(authenticationRequestMock.getScope()).thenReturn(Scope.parse("scope1 scope2"));

        when(httpServletRequestMock.getSession()).thenReturn(httpSessionMock);
        userPrincipal.addUserInfo(WebConstants.SSO_COOKIE_TOKEN, "CookieTokenRememberMe");

        when(httpServletRequestMock.getHeader("User-Agent")).thenReturn("UserAgentValue");
        when(httpServletRequestMock.getRemoteAddr()).thenReturn("remoteAddressValue");

        ClientInfo clientInfo = new ClientInfo();
        String idTokenSecret = "01234567890123456789012345678901234567890";
        clientInfo.setIdTokenSecret(idTokenSecret);

        ClientID clientId = new ClientID("JUnit_client");

        List<Audience> aud = Audience.create("aud");
        IDTokenClaimsSet expectedClaimSet = new IDTokenClaimsSet(new Issuer("issuer"), new Subject("sub"), aud, new Date(), new Date());
        when(oidcTokenHelperMock.defineIDToken(httpServletRequestMock, userPrincipal, clientId, authenticationRequestMock))
                .thenReturn(expectedClaimSet);

        configureTokenSigning(idTokenSecret);

        authenticationServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());

        String callbackURL = stringArgumentCaptor.getValue();
        assertThat(callbackURL).startsWith("http://client.app/testing?id_token=");
        assertThat(callbackURL).endsWith("&state=stateValue");

        String idToken = callbackURL.substring(35, callbackURL.indexOf('&'));

        SignedJWT jwt = SignedJWT.parse(idToken);
        jwt.verify(new MACVerifier(idTokenSecret));

        verify(tokenStoreMock).addLoginFromClient(any(UserPrincipal.class), cookieTokenArgumentCaptor.capture(),
                userAgentArgumentCaptor.capture(), remoteHostArgumentCaptor.capture(), oidcStoreDataArgumentCaptor.capture());

        assertThat(cookieTokenArgumentCaptor.getValue()).isEqualTo("CookieTokenRememberMe");
        assertThat(userAgentArgumentCaptor.getValue()).isEqualTo("UserAgentValue");
        assertThat(remoteHostArgumentCaptor.getValue()).isEqualTo("remoteAddressValue");

        assertThat(oidcStoreDataArgumentCaptor.getValue().getAuthorizationCode()).isNull();
        assertThat(oidcStoreDataArgumentCaptor.getValue().getAccessToken()).isNotNull();
        assertThat(oidcStoreDataArgumentCaptor.getValue().getScope().toStringList()).containsExactly("scope1", "scope2");
        assertThat(oidcStoreDataArgumentCaptor.getValue().getClientId().getValue()).isEqualTo("JUnit_client");

        IDTokenClaimsSet claimsSet = oidcStoreDataArgumentCaptor.getValue().getIdTokenClaimsSet();
        assertThat(claimsSet).isNotSameAs(expectedClaimSet);  // Since it is serialized/Deserialized

        verify(httpSessionMock).invalidate();
    }

    private void configureTokenSigning(final String idTokenSecret) {
        Issuer iss = new Issuer("http://some.host/root");
        Subject sub = new Subject("subject");
        List<Audience> audList = Audience.create("JUnit_client");
        final IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, new Date(), new Date());

        when(oidcTokenHelperMock.signIdToken(any(ClientID.class), any(IDTokenClaimsSet.class))).thenAnswer(new Answer<SignedJWT>() {
            @Override
            public SignedJWT answer(InvocationOnMock invocation) throws Throwable {
                SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());

                idToken.sign(new MACSigner(idTokenSecret));

                return idToken;
            }
        });

    }

    private void verifyContent(JWTClaimsSet jwtClaimsSet, IDTokenClaimsSet expectedClaimSet) {


        try {
            Map<String, Object> claims = jwtClaimsSet.getClaims();
            for (Map.Entry<String, Object> entry : expectedClaimSet.toJWTClaimsSet().getClaims().entrySet()) {
                assertThat(claims).containsKey(entry.getKey());
                assertThat(claims).containsEntry(entry.getKey(), entry.getValue());
            }


        } catch (OAuth2JSONParseException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void doGet_happyCase_ImplicitFlow() throws ServletException, IOException, OAuth2JSONParseException, URISyntaxException, java.text.ParseException {
        when(ssoServerConfigurationMock.getJARMLevel()).thenReturn(JARMLevel.NONE);

        ThreadContext.bind(subjectMock);
        UserPrincipal userPrincipal = new UserPrincipal();
        when(subjectMock.getPrincipal()).thenReturn(userPrincipal);


        when(ssoServerConfigurationMock.getOIDCTokenLength()).thenReturn(48);

        when(httpServletRequestMock.getAttribute(AbstractRequest.class.getName())).thenReturn(authenticationRequestMock);
        when(authenticationRequestMock.getResponseType()).thenReturn(ResponseType.parse("id_token token"));
        when(authenticationRequestMock.getClientID()).thenReturn(new ClientID("JUnit_client"));
        when(authenticationRequestMock.getRedirectionURI()).thenReturn(new URI("http://client.app/testing"));
        when(authenticationRequestMock.getState()).thenReturn(new State("stateValue"));
        when(authenticationRequestMock.getScope()).thenReturn(Scope.parse("scope1 scope2"));

        when(httpServletRequestMock.getSession()).thenReturn(httpSessionMock);
        userPrincipal.addUserInfo(WebConstants.SSO_COOKIE_TOKEN, "CookieTokenRememberMe");

        when(httpServletRequestMock.getHeader("User-Agent")).thenReturn("UserAgentValue");
        when(httpServletRequestMock.getRemoteAddr()).thenReturn("remoteAddressValue");

        ClientInfo clientInfo = new ClientInfo();
        String idTokenSecret = "01234567890123456789012345678901234567890";
        clientInfo.setIdTokenSecret(idTokenSecret);

        configureTokenSigning(idTokenSecret);

        ClientID clientId = new ClientID("JUnit_client");
        List<Audience> aud = Audience.create("aud");
        IDTokenClaimsSet expectedClaimSet = new IDTokenClaimsSet(new Issuer("issuer"), new Subject("sub"), aud, new Date(), new Date());
        when(oidcTokenHelperMock.defineIDToken(httpServletRequestMock, userPrincipal, clientId, authenticationRequestMock))
                .thenReturn(expectedClaimSet);

        authenticationServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());

        String callbackURL = stringArgumentCaptor.getValue();
        assertThat(callbackURL).startsWith("http://client.app/testing?access_token=");

        String query = callbackURL.substring(callbackURL.indexOf('?') + 1);
        Map<String, List<String>> parameters = URLUtils.parseParameters(query);

        assertThat(parameters.keySet()).containsOnly("access_token", "id_token", "state", "token_type", "scope");

        assertThat(parameters.get("state").get(0)).isEqualTo("stateValue");
        assertThat(parameters.get("token_type").get(0)).isEqualTo("Bearer");

        byte[] bytes = Base64.getUrlDecoder().decode(parameters.get("access_token").get(0));
        assertThat(bytes.length >= 45 && bytes.length <= 48).isTrue(); // Don't know why the actual length isn't 48


        String idToken = parameters.get("id_token").get(0);
        SignedJWT jwt = SignedJWT.parse(idToken);
        jwt.verify(new MACVerifier(idTokenSecret));

        verify(tokenStoreMock).addLoginFromClient(any(UserPrincipal.class), cookieTokenArgumentCaptor.capture(),
                userAgentArgumentCaptor.capture(), remoteHostArgumentCaptor.capture(), oidcStoreDataArgumentCaptor.capture());

        assertThat(cookieTokenArgumentCaptor.getValue()).isEqualTo("CookieTokenRememberMe");
        assertThat(userAgentArgumentCaptor.getValue()).isEqualTo("UserAgentValue");
        assertThat(remoteHostArgumentCaptor.getValue()).isEqualTo("remoteAddressValue");

        assertThat(oidcStoreDataArgumentCaptor.getValue().getAuthorizationCode()).isNull();
        assertThat(oidcStoreDataArgumentCaptor.getValue().getAccessToken().getValue()).isEqualTo(parameters.get("access_token").get(0));
        assertThat(oidcStoreDataArgumentCaptor.getValue().getScope().toStringList()).containsExactly("scope1", "scope2");
        assertThat(oidcStoreDataArgumentCaptor.getValue().getClientId().getValue()).isEqualTo("JUnit_client");

        IDTokenClaimsSet claimsSet = oidcStoreDataArgumentCaptor.getValue().getIdTokenClaimsSet();
        assertThat(claimsSet).isNotSameAs(expectedClaimSet);  // Since it is serialized/Deserialized

        verify(httpSessionMock).invalidate();
    }

    @Test
    public void doGet_happyCase_JARM_CodeFlow() throws ServletException, IOException, OAuth2JSONParseException, URISyntaxException, NoSuchFieldException, ParseException {
        when(ssoServerConfigurationMock.getJARMLevel()).thenReturn(JARMLevel.JWS);
        when(ssoServerConfigurationMock.getJarmJWTExpirationTime()).thenReturn("2s");

        when(ssoServerConfigurationMock.getJarmSigningKeyId()).thenReturn("theKid");

        List<AtbashKey> keys = new ArrayList<>();
        keys.add(generatePrivateKey());
        KeyManager listKeyManager = new ListKeyManager(keys);
        when(jwtSupportConfigurationMock.getKeyManager()).thenReturn(listKeyManager);

        TestReflectionUtils.setFieldValue(authenticationServlet, "jwtEncoder", new JWTEncoder());

        ThreadContext.bind(subjectMock);
        UserPrincipal userPrincipal = new UserPrincipal();
        when(subjectMock.getPrincipal()).thenReturn(userPrincipal);

        when(ssoServerConfigurationMock.getOIDCTokenLength()).thenReturn(48);
        when(ssoServerConfigurationMock.getSSOAccessTokenTimeToLive()).thenReturn(3600);

        when(httpServletRequestMock.getAttribute(AbstractRequest.class.getName())).thenReturn(authenticationRequestMock);
        when(authenticationRequestMock.getClientID()).thenReturn(new ClientID("JUnit_client"));
        when(authenticationRequestMock.getResponseType()).thenReturn(ResponseType.parse("code"));
        when(authenticationRequestMock.getRedirectionURI()).thenReturn(new URI("http://client.app/testing"));
        when(authenticationRequestMock.getState()).thenReturn(new State("stateValue"));
        when(authenticationRequestMock.getScope()).thenReturn(Scope.parse("scope1 scope2"));

        when(httpServletRequestMock.getSession()).thenReturn(httpSessionMock);

        userPrincipal.addUserInfo(WebConstants.SSO_COOKIE_TOKEN, "CookieTokenRememberMe");
        when(httpServletRequestMock.getHeader("User-Agent")).thenReturn("UserAgentValue");
        when(httpServletRequestMock.getRemoteAddr()).thenReturn("remoteAddressValue");

        List<Audience> aud = Audience.create("aud");
        IDTokenClaimsSet expectedClaimSet = new IDTokenClaimsSet(new Issuer("issuer"), new Subject("sub"), aud, new Date(), new Date());

        ClientID clientId = new ClientID("JUnit_client");
        when(oidcTokenHelperMock.defineIDToken(httpServletRequestMock, userPrincipal, clientId, authenticationRequestMock))
                .thenReturn(expectedClaimSet);

        authenticationServlet.init();  // To configure the KeyManager

        authenticationServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());

        String callbackURL = stringArgumentCaptor.getValue();
        assertThat(callbackURL).startsWith("http://client.app/testing?response=");

        JWT jwt = JWTParser.parse(callbackURL.substring(35));

        Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();
        assertThat(claims.keySet()).containsOnly("iss", "exp", "aud", "code", "state");

        String authorizationCode = claims.get("code").toString();
        byte[] bytes = new Base64URLValue(authorizationCode).decode();
        assertThat(bytes.length).isEqualTo(48);

        assertThat(claims.get("state")).isEqualTo("stateValue");
        List<String> audience = (List<String>) claims.get("aud");
        assertThat(audience).containsOnly("JUnit_client");

        verify(tokenStoreMock).addLoginFromClient(any(UserPrincipal.class), cookieTokenArgumentCaptor.capture(),
                userAgentArgumentCaptor.capture(), remoteHostArgumentCaptor.capture(), oidcStoreDataArgumentCaptor.capture());

        assertThat(cookieTokenArgumentCaptor.getValue()).isEqualTo("CookieTokenRememberMe");
        assertThat(userAgentArgumentCaptor.getValue()).isEqualTo("UserAgentValue");
        assertThat(remoteHostArgumentCaptor.getValue()).isEqualTo("remoteAddressValue");

        assertThat(oidcStoreDataArgumentCaptor.getValue().getAuthorizationCode().getValue()).isEqualTo(authorizationCode);
        assertThat(oidcStoreDataArgumentCaptor.getValue().getAccessToken()).isNotNull();
        assertThat(oidcStoreDataArgumentCaptor.getValue().getScope().toStringList()).containsExactly("scope1", "scope2");
        assertThat(oidcStoreDataArgumentCaptor.getValue().getClientId().getValue()).isEqualTo("JUnit_client");

        IDTokenClaimsSet claimsSet = oidcStoreDataArgumentCaptor.getValue().getIdTokenClaimsSet();
        assertThat(claimsSet).isNotSameAs(expectedClaimSet);  // Since it is serialized/Deserialized

        verify(httpSessionMock).invalidate();
    }

    @Test
    public void doGet_missingKey_JARM_CodeFlow() throws ServletException, IOException, OAuth2JSONParseException, URISyntaxException, NoSuchFieldException, ParseException {
        when(ssoServerConfigurationMock.getJARMLevel()).thenReturn(JARMLevel.JWS);
        when(ssoServerConfigurationMock.getJarmJWTExpirationTime()).thenReturn("2s");

        when(ssoServerConfigurationMock.getJarmSigningKeyId()).thenReturn("theKid");

        List<AtbashKey> keys = new ArrayList<>();
        KeyManager listKeyManager = new ListKeyManager(keys);
        when(jwtSupportConfigurationMock.getKeyManager()).thenReturn(listKeyManager);

        TestReflectionUtils.setFieldValue(authenticationServlet, "jwtEncoder", new JWTEncoder());

        ThreadContext.bind(subjectMock);
        UserPrincipal userPrincipal = new UserPrincipal();
        when(subjectMock.getPrincipal()).thenReturn(userPrincipal);

        when(ssoServerConfigurationMock.getOIDCTokenLength()).thenReturn(48);
        when(ssoServerConfigurationMock.getSSOAccessTokenTimeToLive()).thenReturn(3600);

        when(httpServletRequestMock.getAttribute(AbstractRequest.class.getName())).thenReturn(authenticationRequestMock);
        when(authenticationRequestMock.getClientID()).thenReturn(new ClientID("JUnit_client"));
        when(authenticationRequestMock.getResponseType()).thenReturn(ResponseType.parse("code"));
        when(authenticationRequestMock.getRedirectionURI()).thenReturn(new URI("http://client.app/testing"));
        when(authenticationRequestMock.getState()).thenReturn(new State("stateValue"));
        when(authenticationRequestMock.getScope()).thenReturn(Scope.parse("scope1 scope2"));

        userPrincipal.addUserInfo(WebConstants.SSO_COOKIE_TOKEN, "CookieTokenRememberMe");

        List<Audience> aud = Audience.create("aud");
        IDTokenClaimsSet expectedClaimSet = new IDTokenClaimsSet(new Issuer("issuer"), new Subject("sub"), aud, new Date(), new Date());

        ClientID clientId = new ClientID("JUnit_client");
        when(oidcTokenHelperMock.defineIDToken(httpServletRequestMock, userPrincipal, clientId, authenticationRequestMock))
                .thenReturn(expectedClaimSet);

        authenticationServlet.init();  // To configure the KeyManager


        Assertions.assertThrows(ConfigurationException.class, () -> authenticationServlet.doGet(httpServletRequestMock, httpServletResponseMock));

        verify(httpServletResponseMock, never()).sendRedirect(anyString());

        verify(tokenStoreMock, never()).addLoginFromClient(any(UserPrincipal.class), anyString(),
                anyString(), anyString(), any(OIDCStoreData.class));

        verify(httpSessionMock, never()).invalidate();

    }

    private static AtbashKey generatePrivateKey() {
        KeyGenerator keyGenerator = new KeyGenerator();
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeySize(2048)
                .withKeyId("theKid")
                .build();
        List<AtbashKey> atbashKeys = keyGenerator.generateKeys(generationParameters);

        ListKeyManager keyManager = new ListKeyManager(atbashKeys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> privateList = keyManager.retrieveKeys(criteria);
        return privateList.get(0);
    }
}