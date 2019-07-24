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

import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.server.requestor.OctopusUserRequestor;
import be.atbash.ee.security.octopus.session.Session;
import be.atbash.ee.security.octopus.session.SessionUtil;
import be.atbash.ee.security.octopus.sso.config.OctopusSSOClientConfiguration;
import be.atbash.ee.security.octopus.sso.core.OctopusRetrievalException;
import be.atbash.ee.security.octopus.sso.core.client.OpenIdVariableClientData;
import be.atbash.ee.security.octopus.sso.core.client.SSOFlow;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOTokenConverter;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.SavedRequest;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.util.TestReflectionUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static be.atbash.ee.security.octopus.util.WebUtils.SAVED_REQUEST_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class SSOCallbackServletTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private HttpSession httpSessionMock;

    @Mock
    private OctopusCoreConfiguration octopusConfigMock;

    @Mock
    private ExchangeForAccessCode exchangeForAccessCodeMock;

    @Mock
    private OctopusSSOClientConfiguration clientConfigurationMock;

    @Mock
    private CallbackErrorHandler callbackErrorHandlerMock;

    @Mock
    private OctopusUserRequestor octopusUserRequestorMock;

    @Mock
    private SessionUtil sessionUtilMock;

    @Mock
    private WebSubject webSubjectMock;

    @Mock
    private Session sessionMock;

    @Captor
    private ArgumentCaptor<ErrorObject> errorObjectArgumentCaptor;

    @Captor
    private ArgumentCaptor<String> stringArgumentCaptor;

    @InjectMocks
    private SSOCallbackServlet callbackServlet;

    @Before
    public void setUp() throws IllegalAccessException {

        TestReflectionUtils.injectDependencies(callbackServlet, new OctopusSSOTokenConverter());
    }

    @Test
    public void doGet_ErrorResponse() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        when(httpServletRequestMock.getQueryString()).thenReturn("error_description=Invalid+request%3A+Missing+%22client_id%22+parameter&state=stateCode&error=invalid_request");

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());

        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("Invalid request: Missing \"client_id\" parameter");
    }

    @Test
    public void doGet_InvalidRequest_NoState() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        when(httpServletRequestMock.getQueryString()).thenReturn("blablabla=wrong");

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());

        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("Request has an invalid 'state' value");
        assertThat(errorObjectArgumentCaptor.getValue().getCode()).isEqualTo("OCT-SSO-CLIENT-011");
    }


    @Test
    public void doGet_InvalidRequest_MissingSession() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);

        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(null);

        //when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());

        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("Request did not originate from this session");
        assertThat(errorObjectArgumentCaptor.getValue().getCode()).isEqualTo("OCT-SSO-CLIENT-012");
    }


    @Test
    public void doGet_WrongState() throws ServletException, IOException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        when(httpServletRequestMock.getQueryString()).thenReturn("code=TheAuthenticationCode&state=stateValue");

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);
        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());

        assertThat(errorObjectArgumentCaptor.getValue().getDescription()).isEqualTo("Request has an invalid 'state' value");
        assertThat(errorObjectArgumentCaptor.getValue().getCode()).isEqualTo("OCT-SSO-CLIENT-011");
    }


    @Test
    public void doGet_MissingAuthorizationCode() throws ServletException, IOException, ParseException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        List<Audience> audience = new ArrayList<Audience>();
        IDTokenClaimsSet tokenClaimsSet = new IDTokenClaimsSet(new Issuer("Issuer")
                , new com.nimbusds.oauth2.sdk.id.Subject("subject"), audience, new Date(), new Date());
        String idToken = new PlainJWT(tokenClaimsSet.toJWTClaimsSet()).serialize();
        when(httpServletRequestMock.getQueryString()).thenReturn("id_token=" + idToken + "&state=" + clientData.getState().getValue());

        when(clientConfigurationMock.getSSOType()).thenReturn(SSOFlow.AUTHORIZATION_CODE);

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());
        assertThat(errorObjectArgumentCaptor.getValue().getCode()).isEqualTo("OCT-SSO-CLIENT-013");
    }

    @Test
    public void doGet_ValidAuthenticationToken() throws ServletException, IOException, java.text.ParseException, JOSEException, OctopusRetrievalException, ParseException, URISyntaxException {
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        // For AUTHORIZATION_CODE we need parameter code
        when(httpServletRequestMock.getQueryString()).thenReturn("code=TheAuthorizationCode&state=" + clientData.getState().getValue());

        when(clientConfigurationMock.getSSOType()).thenReturn(SSOFlow.AUTHORIZATION_CODE);


        AuthorizationCode authorizationCode = new AuthorizationCode("TheAuthorizationCode");
        when(exchangeForAccessCodeMock.doExchange(httpServletResponseMock, clientData, authorizationCode)).thenReturn(new BearerAccessToken("TheAccessToken"));

        BearerAccessToken accessToken = new BearerAccessToken("TheAccessToken");
        OctopusSSOToken ssoUser = new OctopusSSOToken();
        when(octopusUserRequestorMock.getOctopusSSOUser(clientData, accessToken)).thenReturn(ssoUser);

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getSession(false)).thenReturn(sessionMock);
        when(webSubjectMock.getSession()).thenReturn(sessionMock);
        when(httpServletRequestMock.getRequestURI()).thenReturn("http://host.to.saved.request/root");
        SavedRequest savedRequest = new SavedRequest(httpServletRequestMock);
        when(sessionMock.getAttribute(WebUtils.SAVED_REQUEST_KEY)).thenReturn(savedRequest);

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(sessionUtilMock).invalidateCurrentSession(httpServletRequestMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());
        assertThat(stringArgumentCaptor.getValue()).startsWith("http://host.to.saved.request/root?code=TheAuthorizationCode&state=");
        // The query part is added to requestURL because it was mocked earlier like that to have a correct behaviour for other parts (state is variable !)

        verify(callbackErrorHandlerMock, never()).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());

    }

    @Test
    public void doGet_ValidAccessToken() throws ServletException, IOException, java.text.ParseException, JOSEException, OctopusRetrievalException, ParseException, URISyntaxException {
        // Implicit flow
        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);
        OpenIdVariableClientData clientData = new OpenIdVariableClientData("someRoot");
        when(httpSessionMock.getAttribute(OpenIdVariableClientData.class.getName())).thenReturn(clientData);

        // For IMPLICIT we need access_token
        when(httpServletRequestMock.getQueryString()).thenReturn("access_token=TheToken&token_type=Bearer&state=" + clientData.getState().getValue());

        when(clientConfigurationMock.getSSOType()).thenReturn(SSOFlow.IMPLICIT);

        BearerAccessToken accessToken = new BearerAccessToken("TheToken");
        OctopusSSOToken ssoUser = new OctopusSSOToken();
        when(octopusUserRequestorMock.getOctopusSSOUser(clientData, accessToken)).thenReturn(ssoUser);

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getSession(false)).thenReturn(sessionMock);
        when(webSubjectMock.getSession()).thenReturn(sessionMock);
        when(httpServletRequestMock.getRequestURI()).thenReturn("http://host.to.saved.request/root");
        SavedRequest savedRequest = new SavedRequest(httpServletRequestMock);
        when(sessionMock.getAttribute(SAVED_REQUEST_KEY)).thenReturn(savedRequest);

        callbackServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(sessionUtilMock).invalidateCurrentSession(httpServletRequestMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());
        assertThat(stringArgumentCaptor.getValue()).startsWith("http://host.to.saved.request/root?access_token=TheToken&token_type=Bearer&state=");
        // The query part is added to requestURL because it was mocked earlier like that to have a correct behaviour for other parts (state is variable !)

        verify(callbackErrorHandlerMock, never()).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCaptor.capture());

    }

    // TODO other scenarios.
}