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
package be.atbash.ee.security.octopus.cas.servlet;

import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.cas.adapter.CasUserToken;
import be.atbash.ee.security.octopus.cas.adapter.info.CasInfoProvider;
import be.atbash.ee.security.octopus.cas.exception.CasAuthenticationException;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.session.Session;
import be.atbash.ee.security.octopus.session.SessionUtil;
import be.atbash.ee.security.octopus.session.usage.ActiveSessionRegistry;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.SavedRequest;
import be.atbash.util.TestReflectionUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static be.atbash.ee.security.octopus.util.WebUtils.SAVED_REQUEST_KEY;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class CasServletTest {

    private CasServlet casServlet;

    @Mock
    private HttpServletRequest requestMock;

    @Mock
    private HttpServletResponse responseMock;

    @Mock
    private CasInfoProvider casInfoProviderMock;

    @Mock
    private SessionUtil sessionUtilMock;

    @Mock
    private ActiveSessionRegistry activeSessionRegistryMock;

    @Mock
    private OctopusJSFConfiguration jsfConfigurationMock;

    @Mock
    private WebSubject subjectMock;

    @Mock
    private Session sessionMock;

    @Mock
    private HttpSession httpSessionMock;

    @Mock
    private SavedRequest savedRequestMock;

    @Before
    public void setUp() throws Exception {
        casServlet = new CasServlet();
        TestReflectionUtils.injectDependencies(casServlet, casInfoProviderMock, sessionUtilMock, activeSessionRegistryMock, jsfConfigurationMock);

        ThreadContext.bind(subjectMock);
    }

    @Test
    public void doGet() throws ServletException, IOException {
        CasUserToken casUser = new CasUserToken("ST1");

        when(requestMock.getParameter("ticket")).thenReturn("ST1");
        when(casInfoProviderMock.retrieveUserInfo("ST1")).thenReturn(casUser);
        when(subjectMock.getSession(false)).thenReturn(sessionMock);
        when(subjectMock.getSession()).thenReturn(sessionMock);
        when(sessionMock.getAttribute(SAVED_REQUEST_KEY)).thenReturn(savedRequestMock);
        when(savedRequestMock.getRequestUrl()).thenReturn("redirectURL");

        casServlet.doGet(requestMock, responseMock);

        verify(sessionUtilMock).invalidateCurrentSession(requestMock);
        verify(subjectMock).login(casUser);
        verify(responseMock).sendRedirect("redirectURL");
    }

    @Test
    public void doGet_AuthenticationException() throws ServletException, IOException {
        CasUserToken casUser = new CasUserToken("ST1");

        when(requestMock.getParameter("ticket")).thenReturn("ST1");
        when(casInfoProviderMock.retrieveUserInfo("ST1")).thenThrow(new CasAuthenticationException("Error"));
        when(requestMock.getSession()).thenReturn(httpSessionMock);
        when(requestMock.getContextPath()).thenReturn("/root");
        when(jsfConfigurationMock.getUnauthorizedExceptionPage()).thenReturn("/unauthorized.xhtml");

        casServlet.doGet(requestMock, responseMock);

        verify(sessionUtilMock, never()).invalidateCurrentSession(requestMock);
        verify(subjectMock, never()).login(casUser);
        verify(responseMock).sendRedirect("/root/unauthorized.xhtml");
    }
}