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
package be.atbash.ee.security.octopus.sso.callback;

import be.atbash.ee.oauth2.sdk.AuthorizationCode;
import be.atbash.ee.oauth2.sdk.ErrorObject;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.openid.connect.sdk.AuthenticationSuccessResponse;
import be.atbash.ee.security.octopus.sso.client.OpenIdVariableClientData;
import be.atbash.ee.security.octopus.sso.client.requestor.OctopusUserRequestor;
import be.atbash.ee.security.octopus.sso.core.OctopusRetrievalException;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class SSOCallbackServletHandlerTest {


    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private CallbackErrorHandler callbackErrorHandlerMock;

    private SSOCallbackServletHandler handler;

    @Mock
    private ExchangeForAccessCode exchangeForAccessCodeMock;

    @Mock
    private OctopusUserRequestor octopusUserRequestorMock;

    @Captor
    private ArgumentCaptor<ErrorObject> errorObjectArgumentCapture;

    private OpenIdVariableClientData variableClientData;

    @BeforeEach
    public void setup() {
        variableClientData = new OpenIdVariableClientData("app1");

        handler = new SSOCallbackServletHandler(httpServletRequestMock, httpServletResponseMock, variableClientData, callbackErrorHandlerMock, null);
    }

    @Test
    public void getAuthenticationResponse_happyCase() {

        when(httpServletRequestMock.getQueryString()).thenReturn("code=authenticationCode&state=" + variableClientData.getState().getValue());

        AuthenticationSuccessResponse successResponse = handler.getAuthenticationResponse();
        verify(callbackErrorHandlerMock, never()).showErrorMessage(any(HttpServletResponse.class), any(ErrorObject.class));

        assertThat(successResponse).isNotNull();
        assertThat(successResponse.getAuthorizationCode().getValue()).isEqualTo("authenticationCode");
        assertThat(successResponse.getAccessToken()).isNull();
        assertThat(successResponse.getIDToken()).isNull();  // FIXME correct?

        verify(callbackErrorHandlerMock, never()).showErrorMessage(any(HttpServletResponse.class), any(ErrorObject.class));
    }

    @Test
    public void getAuthenticationResponse_wrongState() {
        when(httpServletRequestMock.getQueryString()).thenReturn("code=authenticationCode&state=someValue");

        AuthenticationSuccessResponse successResponse = handler.getAuthenticationResponse();

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCapture.capture());
        ErrorObject error = errorObjectArgumentCapture.getValue();
        assertThat(error.getCode()).isEqualTo("OCT-SSO-CLIENT-011");
        assertThat(error.getDescription()).isEqualTo("Request has an invalid 'state' value");

        assertThat(successResponse).isNull();
    }

    @Test
    public void getAuthenticationResponse_errorResponse() {
        when(httpServletRequestMock.getQueryString()).thenReturn("error=xyz&error_description=testError&state=" + variableClientData.getState().getValue());

        AuthenticationSuccessResponse successResponse = handler.getAuthenticationResponse();

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCapture.capture());
        ErrorObject error = errorObjectArgumentCapture.getValue();
        assertThat(error.getCode()).isEqualTo("xyz");
        assertThat(error.getDescription()).isEqualTo("testError");

        assertThat(successResponse).isNull();
    }

    @Test
    public void getAuthenticationResponse_onlyState() {
        when(httpServletRequestMock.getQueryString()).thenReturn("some=query&parameters=which&have=nothing@todo=with&openid=connect&state=" + variableClientData.getState().getValue());

        AuthenticationSuccessResponse successResponse = handler.getAuthenticationResponse();

        assertThat(successResponse).isNotNull();
        assertThat(successResponse.getAuthorizationCode()).isNull();
        assertThat(successResponse.getAccessToken()).isNull();
        assertThat(successResponse.getIDToken()).isNull();

        verify(callbackErrorHandlerMock, never()).showErrorMessage(any(HttpServletResponse.class), any(ErrorObject.class));
    }

    @Test
    public void getAccessTokenFromAuthorizationCode_happyCase() {
        URI uri = URI.create("?");
        AuthorizationCode authorizationCode = new AuthorizationCode("authCode");
        AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(uri, authorizationCode, null, null, null, null, null);

        BearerAccessToken accessToken = new BearerAccessToken("accessToken");
        // variableClientData null because not set by call  getAuthenticationResponse but in real life, never null
        when(exchangeForAccessCodeMock.doExchange(httpServletResponseMock, variableClientData, authorizationCode)).thenReturn(accessToken);

        BearerAccessToken result = handler.getAccessTokenFromAuthorizationCode(successResponse, exchangeForAccessCodeMock);
        assertThat(result).isNotNull();
        assertThat(result).isSameAs(accessToken);

        verify(callbackErrorHandlerMock, never()).showErrorMessage(any(HttpServletResponse.class), any(ErrorObject.class));
    }

    @Test
    public void getAccessTokenFromAuthorizationCode_missingAuthorizationCode() {
        URI uri = URI.create("?");

        AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(uri, null, null, null, null, null, null);

        BearerAccessToken result = handler.getAccessTokenFromAuthorizationCode(successResponse, exchangeForAccessCodeMock);
        assertThat(result).isNull();

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCapture.capture());
        ErrorObject error = errorObjectArgumentCapture.getValue();
        assertThat(error.getCode()).isEqualTo("OCT-SSO-CLIENT-013");
        assertThat(error.getDescription()).isEqualTo("Missing Authorization code");

    }

    @Test
    public void retrieveUser_happyCase() throws ParseException, OctopusRetrievalException, OAuth2JSONParseException, URISyntaxException {
        BearerAccessToken accessToken = new BearerAccessToken("accessToken");

        // variableClientData null because not set by call  getAuthenticationResponse but in real life, never null
        OctopusSSOToken ssoToken = new OctopusSSOToken();
        when(octopusUserRequestorMock.getOctopusSSOToken(variableClientData, accessToken)).thenReturn(ssoToken);

        OctopusSSOToken result = handler.retrieveUser(octopusUserRequestorMock, accessToken);
        assertThat(result).isNotNull();
        assertThat(result).isSameAs(ssoToken);

        verify(callbackErrorHandlerMock, never()).showErrorMessage(any(HttpServletResponse.class), any(ErrorObject.class));
    }

    @Test
    public void retrieveUser_OctopusRetrievalException() throws ParseException, OctopusRetrievalException, OAuth2JSONParseException, URISyntaxException {
        BearerAccessToken accessToken = new BearerAccessToken("accessToken");

        // variableClientData null because not set by call  getAuthenticationResponse but in real life, never null

        ErrorObject errorObject = new ErrorObject("xyz", "description");
        OctopusRetrievalException octopusRetrievalException = new OctopusRetrievalException(errorObject);
        when(octopusUserRequestorMock.getOctopusSSOToken(variableClientData, accessToken)).thenThrow(octopusRetrievalException);

        OctopusSSOToken result = handler.retrieveUser(octopusUserRequestorMock, accessToken);
        assertThat(result).isNull();

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCapture.capture());
        ErrorObject error = errorObjectArgumentCapture.getValue();
        assertThat(error.getCode()).isEqualTo("xyz");
        assertThat(error.getDescription()).isEqualTo("description");

    }

    @Test
    public void retrieveUser_ParseException() throws ParseException, OctopusRetrievalException, OAuth2JSONParseException, URISyntaxException {
        BearerAccessToken accessToken = new BearerAccessToken("accessToken");

        // variableClientData null because not set by call  getAuthenticationResponse but in real life, never null

        ParseException parseException = new ParseException("Something went wrong", 12);
        when(octopusUserRequestorMock.getOctopusSSOToken(variableClientData, accessToken)).thenThrow(parseException);

        OctopusSSOToken result = handler.retrieveUser(octopusUserRequestorMock, accessToken);
        assertThat(result).isNull();

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCapture.capture());
        ErrorObject error = errorObjectArgumentCapture.getValue();
        assertThat(error.getCode()).isEqualTo("OCT-SSO-CLIENT-018");
        assertThat(error.getDescription()).isEqualTo("User Info endpoint response JWT validation failure : Something went wrong");

    }

    @Test
    public void retrieveUser_ParseException2() throws ParseException, OctopusRetrievalException, OAuth2JSONParseException, URISyntaxException {
        BearerAccessToken accessToken = new BearerAccessToken("accessToken");

        // variableClientData null because not set by call  getAuthenticationResponse but in real life, never null

        OAuth2JSONParseException parseException = new OAuth2JSONParseException("Something went wrong");
        when(octopusUserRequestorMock.getOctopusSSOToken(variableClientData, accessToken)).thenThrow(parseException);

        OctopusSSOToken result = handler.retrieveUser(octopusUserRequestorMock, accessToken);
        assertThat(result).isNull();

        verify(callbackErrorHandlerMock).showErrorMessage(any(HttpServletResponse.class), errorObjectArgumentCapture.capture());
        ErrorObject error = errorObjectArgumentCapture.getValue();
        assertThat(error.getCode()).isEqualTo("OCT-SSO-CLIENT-017");
        assertThat(error.getDescription()).isEqualTo("User Info endpoint response validation failure : Something went wrong");

    }
}