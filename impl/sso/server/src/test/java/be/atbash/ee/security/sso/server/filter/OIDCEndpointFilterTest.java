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
package be.atbash.ee.security.sso.server.filter;

import be.atbash.ee.oauth2.sdk.AbstractRequest;
import be.atbash.ee.oauth2.sdk.TokenRequest;
import be.atbash.ee.oauth2.sdk.auth.ClientAuthentication;
import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.auth.ClientSecretJWT;
import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.openid.connect.sdk.AuthenticationRequest;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.filter.SessionHijackingFilter;
import be.atbash.ee.security.octopus.filter.authc.AbstractUserFilter;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.session.Session;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.PatternMatcher;
import be.atbash.ee.security.octopus.util.SavedRequest;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.ee.security.sso.server.client.ClientInfo;
import be.atbash.ee.security.sso.server.client.ClientInfoRetriever;
import be.atbash.ee.security.sso.server.cookie.SSOHelper;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class OIDCEndpointFilterTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private ClientInfoRetriever clientInfoRetrieverMock;

    @Mock
    private SSOHelper ssoHelperMock;

    @Mock
    private WebSubject webSubjectMock;

    @Mock
    private PrintWriter printWriterMock;

    @Mock
    private OctopusClientCredentialsSelector clientCredentialsSelectorMock;

    @Mock
    private AbstractUserFilter abstractUserFilterMock;

    @Mock
    private PatternMatcher patternMatcherMock;

    @Mock
    private Session sessionMock;

    @Captor
    private ArgumentCaptor<AuthenticationRequest> authenticationRequestCapture;

    @Captor
    private ArgumentCaptor<String> stringCapture;

    @Captor
    private ArgumentCaptor<SavedRequest> savedRequestCapture;

    @InjectMocks
    private OIDCEndpointFilter endpointFilter;

    private BeanManagerFake beanManagerFake;

    @Captor
    private ArgumentCaptor<String> attributeNameCapture;

    @Captor
    private ArgumentCaptor<Object> attributeValueCapture;

    @BeforeEach
    public void setup() {

        beanManagerFake = new BeanManagerFake();
        beanManagerFake.registerBean(clientInfoRetrieverMock, ClientInfoRetriever.class);
        beanManagerFake.registerBean(ssoHelperMock, SSOHelper.class);
        beanManagerFake.registerBean(clientCredentialsSelectorMock, OctopusClientCredentialsSelector.class);
        beanManagerFake.registerBean(abstractUserFilterMock, AbstractUserFilter.class);
        SessionHijackingFilter filter = new SessionHijackingFilter();
        filter.init();
        beanManagerFake.registerBean(filter, SessionHijackingFilter.class);

        beanManagerFake.endRegistration();

        endpointFilter.init();
        //endpointFilter.setUserFilter(new OctopusUserFilter());

        // So that encodeRedirectURL just returns the URL (as no encoding required but want to parameter as return value.
        lenient().when(httpServletResponseMock.encodeRedirectURL(anyString())).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                return invocation.getArgument(0);
            }
        });
    }

    @AfterEach
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void onPreHandle_authenticate_happyCase_unauthenticated() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");  // determines type of call
        String queryString = "response_type=code&client_id=demo-clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode";
        when(httpServletRequestMock.getQueryString()).thenReturn(queryString);

        when(httpServletRequestMock.getContextPath()).thenReturn("/oidc");  // The context root of the SSO app

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getPrincipal()).thenReturn(null);  // No UserPrincipal so that we get a redirect ro getLoginURL of UserFilter
        when(webSubjectMock.getSession()).thenReturn(sessionMock);

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setOctopusClient(true);
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2");
        when(clientInfoRetrieverMock.retrieveInfo("demo-clientId")).thenReturn(clientInfo);

        when(abstractUserFilterMock.getLoginUrl()).thenReturn("http://localhost:8080/sso");
        when(patternMatcherMock.matches(anyString(), anyString())).thenReturn(false); // isLoginRequest() -> False since /octopus/sso/authenticate is not the loginRequest for the app.

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock);
        assertThat(data).isEqualTo(false);

        verify(httpServletRequestMock).setAttribute(stringCapture.capture(), authenticationRequestCapture.capture());

        assertThat(stringCapture.getValue()).isEqualTo(AbstractRequest.class.getName());
        assertThat(authenticationRequestCapture.getValue()).isInstanceOf(AuthenticationRequest.class);

        verify(ssoHelperMock).markAsSSOLogin(httpServletRequestMock, "demo-clientId");

        verify(sessionMock).setAttribute(stringCapture.capture(), savedRequestCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo(WebUtils.SAVED_REQUEST_KEY);
        assertThat(savedRequestCapture.getValue().getRequestUrl()).isEqualTo("/octopus/sso/authenticate?" + queryString);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("http://localhost:8080/sso");
    }

    @Test
    public void onPreHandle_authenticate_happyCase_authenticated() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");  // determines type of call
        String queryString = "response_type=code&client_id=demo-clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode";
        when(httpServletRequestMock.getQueryString()).thenReturn(queryString);

        when(httpServletRequestMock.getContextPath()).thenReturn("/oidc");  // The context root of the SSO app

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getPrincipal()).thenReturn(new UserPrincipal());  // any UserPrincipal so that we get a forward to

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setOctopusClient(true);
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2");
        when(clientInfoRetrieverMock.retrieveInfo("demo-clientId")).thenReturn(clientInfo);

        when(abstractUserFilterMock.getLoginUrl()).thenReturn("http://localhost:8080/sso");
        when(patternMatcherMock.matches(anyString(), anyString())).thenReturn(false); // isLoginRequest() -> False since /octopus/sso/authenticate is not the loginRequest for the app.

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock);
        assertThat(data).isEqualTo(true);

        verify(httpServletRequestMock).setAttribute(stringCapture.capture(), authenticationRequestCapture.capture());

        assertThat(stringCapture.getValue()).isEqualTo(AbstractRequest.class.getName());
        assertThat(authenticationRequestCapture.getValue()).isInstanceOf(AuthenticationRequest.class);

        verify(ssoHelperMock).markAsSSOLogin(httpServletRequestMock, "demo-clientId");

        verify(sessionMock, never()).setAttribute(anyString(), any(SavedRequest.class));

        verify(httpServletResponseMock, never()).sendRedirect(anyString());

    }

    @Test
    public void onPreHandle_authenticate_MissingClientId() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode");

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("http://localhost:8080/sso-app2/sso/SSOCallback?error=invalid_request&error_description=Invalid+request%3A+Missing+%22client_id%22+parameter&state=stateCode");
        verifyNoMoreInteractions(ssoHelperMock);
        verify(sessionMock, never()).setAttribute(anyString(), any(SavedRequest.class));

    }

    @Test
    public void onPreHandle_authenticate_MissingClientId_NoValidRedirect() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&redirect_uri=sso-app2&scope=openid&state=stateCode&nonce=nonceCode");

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("sso-app2?error=invalid_request&error_description=Invalid+request%3A+Missing+%22client_id%22+parameter&state=stateCode");
        verifyNoMoreInteractions(ssoHelperMock);
        verify(sessionMock, never()).setAttribute(anyString(), any(SavedRequest.class));
    }

    @Test
    public void onPreHandle_authenticate_MissingRedirectURI() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&client_id=demo-clientId&scope=openid&state=stateCode&nonce=nonceCode");

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock);
        assertThat(data).isEqualTo(false);

        verify(printWriterMock).println(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("Invalid request: Missing \"redirect_uri\" parameter");
        verify(sessionMock, never()).setAttribute(anyString(), any(SavedRequest.class));
    }

    @Test
    public void onPreHandle_authenticate_unknownClientId() throws Exception {
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&client_id=demo-clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode");

        when(clientInfoRetrieverMock.retrieveInfo("demo-clientId")).thenReturn(null);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("http://localhost:8080/sso-app2/sso/SSOCallback?error=invalid_client&error_description=Client+authentication+failed%3A+Unknown+%22client_id%22+parameter+value&state=stateCode");

        verify(httpServletRequestMock, never()).setAttribute(stringCapture.capture(), authenticationRequestCapture.capture());
        verifyNoMoreInteractions(ssoHelperMock);
        verify(sessionMock, never()).setAttribute(anyString(), any(SavedRequest.class));
    }

    @Test
    public void onPreHandle_authenticate_unknownRedirectURI() throws Exception {

        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/authenticate");
        when(httpServletRequestMock.getQueryString()).thenReturn("response_type=code&client_id=demo-clientId&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Fsso%2FSSOCallback&scope=openid&state=stateCode&nonce=nonceCode");

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setOctopusClient(true);
        clientInfo.setCallbackURL("http://localhost:8080/sso-app1");
        when(clientInfoRetrieverMock.retrieveInfo("demo-clientId")).thenReturn(clientInfo);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).sendRedirect(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("http://localhost:8080/sso-app2/sso/SSOCallback?error=invalid_client&error_description=Client+authentication+failed%3A+Unknown+%22redirect_uri%22+parameter+value&state=stateCode");

        verify(httpServletRequestMock, never()).setAttribute(stringCapture.capture(), authenticationRequestCapture.capture());
        verifyNoMoreInteractions(ssoHelperMock);
        verify(sessionMock, never()).setAttribute(anyString(), any(SavedRequest.class));
    }

    @Test
    public void onPreHandle_token_happyCase() throws Exception {

        StringBuffer url = new StringBuffer();
        url.append("http://some.server/oidc/octopus/sso/token");
        when(httpServletRequestMock.getRequestURL()).thenReturn(url);
        when(httpServletRequestMock.getMethod()).thenReturn("POST");
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/token");

        String secretString = generateSecret();

        String jwtData = generateJWT("junit_client_id", secretString, new URI("http://some.server/oidc/octopus/sso/token"));
        String body = jwtData + "&code=81np_6iMIkw52117lb_YF71seITMdzOGqmyC02se3jY&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Fsso%2FSSOCallback";

        // Read the info from the client
        BufferedReader readerMock = Mockito.mock(BufferedReader.class);
        when(readerMock.readLine()).thenReturn(body);
        when(httpServletRequestMock.getReader()).thenReturn(readerMock);

        // To make the rest of the code happy
        when(httpServletRequestMock.getContextPath()).thenReturn("/oidc");
        ThreadContext.bind(webSubjectMock);  // So that the .login doesn't complain
        when(webSubjectMock.getPrincipal()).thenReturn(new UserPrincipal());  // Since we have a login performed, we have a UserPrincipal

        // Client JWT validation
        List<Secret> secrets = new ArrayList<>();
        secrets.add(new Secret(secretString));
        when(clientCredentialsSelectorMock.selectClientSecrets(new ClientID("junit_client_id"), ClientAuthenticationMethod.CLIENT_SECRET_JWT, null)).thenReturn(secrets);

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setOctopusClient(true);
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2");
        when(clientInfoRetrieverMock.retrieveInfo("junit_client_id")).thenReturn(clientInfo);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock);
        assertThat(data).isEqualTo(true);

        verify(httpServletRequestMock, times(1)).setAttribute(attributeNameCapture.capture(), attributeValueCapture.capture());

        assertThat(attributeNameCapture.getAllValues().get(0)).isEqualTo(AbstractRequest.class.getName());
        Object value1 = attributeValueCapture.getAllValues().get(0);
        assertThat(value1).isInstanceOf(TokenRequest.class);

        // Disabling sh doesn't seems to be necessary anymore.
        //assertThat(attributeNameCapture.getAllValues().get(1)).isEqualTo("sh.FILTERED");
        //Object value2 = attributeValueCapture.getAllValues().get(1);
        //assertThat(value2).isEqualTo(Boolean.TRUE);

        verify(webSubjectMock).getPrincipal();
    }

    @Test
    public void onPreHandle_token_missingClientAuth() throws Exception {

        StringBuffer url = new StringBuffer();
        url.append("http://some.server/oidc/octopus/sso/token");
        when(httpServletRequestMock.getRequestURL()).thenReturn(url);
        when(httpServletRequestMock.getMethod()).thenReturn("POST");
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/token");

        String body = "client_id=junit-client&code=81np_6iMIkw52117lb_YF71seITMdzOGqmyC02se3jY&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Fsso%2FSSOCallback";

        // Read the info from the client
        BufferedReader readerMock = Mockito.mock(BufferedReader.class);
        when(readerMock.readLine()).thenReturn(body);
        when(httpServletRequestMock.getReader()).thenReturn(readerMock);

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock);
        assertThat(data).isEqualTo(false);

        verify(httpServletRequestMock, never()).setAttribute(attributeNameCapture.capture(), attributeValueCapture.capture());

        verify(httpServletResponseMock).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        verify(printWriterMock).println(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("{\"error\":\"OCT-SSO-SERVER-014\",\"error_description\":\"Client authentication required\"}");

        verify(webSubjectMock, never()).getPrincipal();
    }

    @Test
    public void onPreHandle_token_happyCase_fromAdditional() throws Exception {
        // Get value from additional_callback_url
        StringBuffer url = new StringBuffer();
        url.append("http://some.server/oidc/octopus/sso/token");
        when(httpServletRequestMock.getRequestURL()).thenReturn(url);
        when(httpServletRequestMock.getMethod()).thenReturn("POST");
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/token");

        String secretString = generateSecret();

        String jwtData = generateJWT("junit_client_id", secretString, new URI("http://some.server/oidc/octopus/sso/token"));
        String body = jwtData + "&code=81np_6iMIkw52117lb_YF71seITMdzOGqmyC02se3jY&grant_type=authorization_code&redirect_uri=http%3A%2F%2Falias%2Fsso-app2%2Fsso%2FSSOCallback";

        // Read the info from the client
        BufferedReader readerMock = Mockito.mock(BufferedReader.class);
        when(readerMock.readLine()).thenReturn(body);
        when(httpServletRequestMock.getReader()).thenReturn(readerMock);

        // To make the rest of the code happy
        when(httpServletRequestMock.getContextPath()).thenReturn("/oidc");
        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getPrincipal()).thenReturn(new UserPrincipal());  // Anything will do as principal

        // Client JWT validation
        List<Secret> secrets = new ArrayList<>();
        secrets.add(new Secret(secretString));
        when(clientCredentialsSelectorMock.selectClientSecrets(new ClientID("junit_client_id"), ClientAuthenticationMethod.CLIENT_SECRET_JWT, null)).thenReturn(secrets);

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setOctopusClient(true);
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2");
        clientInfo.additionalCallbackURL("http://alias/sso-app2");
        when(clientInfoRetrieverMock.retrieveInfo("junit_client_id")).thenReturn(clientInfo);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock);
        assertThat(data).isEqualTo(true);

        verify(httpServletRequestMock, times(1)).setAttribute(attributeNameCapture.capture(), attributeValueCapture.capture());

        assertThat(attributeNameCapture.getAllValues().get(0)).isEqualTo(AbstractRequest.class.getName());
        Object value1 = attributeValueCapture.getAllValues().get(0);
        assertThat(value1).isInstanceOf(TokenRequest.class);

        //assertThat(attributeNameCapture.getAllValues().get(1)).isEqualTo("sh.FILTERED");
        //Object value2 = attributeValueCapture.getAllValues().get(1);
        //assertThat(value2).isEqualTo(Boolean.TRUE);

        verify(webSubjectMock).getPrincipal();
    }

    private String generateSecret() {
        byte[] secret = new byte[32];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(secret);
        return Base64.getEncoder().withoutPadding().encodeToString(secret);
    }

    private String generateJWT(String ssoClientId, String ssoClientSecret, URI tokenEndPoint) throws MalformedURLException {
        HTTPRequest httpRequest = null;

        httpRequest = new HTTPRequest(HTTPRequest.Method.valueOf("POST"), new URL("http://some.server/oidc"));
        ClientAuthentication clientAuth = new ClientSecretJWT(new ClientID(ssoClientId)
                , tokenEndPoint, JWSAlgorithm.HS256, new Secret(ssoClientSecret)); //ssoClientSecret is actually a Base64 encoded byte Array
        // When we need to be completely correct, we should use the UTF-8 representation of the ByteArray itself to pass to new Secret()

        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        clientAuth.applyTo(httpRequest);


        return httpRequest.getQuery();
    }

    @Test
    public void onPreHandle_token_NoClientAuth() throws Exception {

        StringBuffer url = new StringBuffer();
        url.append("http://some.server/oidc/octopus/sso/token");
        when(httpServletRequestMock.getRequestURL()).thenReturn(url);
        when(httpServletRequestMock.getMethod()).thenReturn("POST");
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/token");

        BufferedReader readerMock = Mockito.mock(BufferedReader.class);
        when(readerMock.readLine()).thenReturn("code=81np_6iMIkw52117lb_YF71seITMdzOGqmyC02se3jY&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback");
        when(httpServletRequestMock.getReader()).thenReturn(readerMock);

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        verify(printWriterMock).println(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("{\"error\":\"invalid_request\",\"error_description\":\"Invalid request: Missing required \\\"client_id\\\" parameter\"}");

        verify(httpServletRequestMock, never()).setAttribute(anyString(), ArgumentMatchers.any());
    }

    @Test
    public void onPreHandle_token_MissingAuthorizationCode() throws Exception {

        StringBuffer url = new StringBuffer();
        url.append("http://some.server/oidc/octopus/sso/token");
        when(httpServletRequestMock.getRequestURL()).thenReturn(url);
        when(httpServletRequestMock.getMethod()).thenReturn("POST");
        when(httpServletRequestMock.getRequestURI()).thenReturn("/octopus/sso/token");

        BufferedReader readerMock = Mockito.mock(BufferedReader.class);
        when(readerMock.readLine()).thenReturn("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso-app2%2Foctopus%2Fsso%2FSSOCallback&client_assertion=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJkZW1vLWNsaWVudElkIiwiYXVkIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL3NlY3VyaXR5XC9vY3RvcHVzXC9zc29cL3Rva2VuIiwiaXNzIjoiZGVtby1jbGllbnRJZCIsImV4cCI6MTQ4OTQ5NzY5NywianRpIjoiOWJXQmRlU3pNdnhCbDJiTmpkc1lrN2NiN2VqU092ZDJWVnpqS2VETFNZcyJ9.2pPH6hqARMyRDpW7kn00qVgeN7y0UF0iDgNeyX-1gkshDJBCKmt7NcqgRPTLUh05VY7az0N98cRS608KzfJ2oQ");
        when(httpServletRequestMock.getReader()).thenReturn(readerMock);

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        boolean data = endpointFilter.onPreHandle(httpServletRequestMock, httpServletResponseMock);
        assertThat(data).isEqualTo(false);

        verify(httpServletResponseMock).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        verify(printWriterMock).println(stringCapture.capture());
        assertThat(stringCapture.getValue()).isEqualTo("{\"error\":\"invalid_request\",\"error_description\":\"Invalid request: Missing or empty \\\"code\\\" parameter\"}");

        verify(httpServletRequestMock, never()).setAttribute(anyString(), ArgumentMatchers.any());
    }

    // FIXME, token endpoint with Password grant.
}