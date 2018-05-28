/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.filter.authz;

import be.atbash.ee.security.octopus.authc.AbstractUserFilter;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.filter.authc.BasicHttpAuthenticationFilter;
import be.atbash.ee.security.octopus.filter.authc.UserFilter;
import be.atbash.ee.security.octopus.filter.mgt.FilterChainManager;
import be.atbash.ee.security.octopus.subject.WebSubject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class JSFAccessDeniedHandlerTest {

    @Mock
    private OctopusJSFConfiguration jsfConfigurationMock;

    @Mock
    private FilterChainManager chainManagerMock;

    @Mock
    private WebSubject subjectMock;

    @Mock
    private HttpServletRequest servletRequestMock;

    @Mock
    private HttpServletResponse servletResponseMock;

    @Mock
    private AbstractUserFilter userFilterMock;

    @InjectMocks
    private JSFAccessDeniedHandler accessDeniedHandler;

    @Captor
    private ArgumentCaptor<String> urlCaptor;

    @Test
    public void init_correctDefaultFilter() {
        when(jsfConfigurationMock.getDefaultUserFilter()).thenReturn("user");
        when(chainManagerMock.getFilter("user")).thenReturn(new UserFilter());
        accessDeniedHandler.init();
    }

    @Test(expected = ConfigurationException.class)
    public void init_WrongDefaultFilter() {
        when(jsfConfigurationMock.getDefaultUserFilter()).thenReturn("basic");
        when(chainManagerMock.getFilter("basic")).thenReturn(new BasicHttpAuthenticationFilter());
        accessDeniedHandler.init();
    }

    @Test(expected = ConfigurationException.class)
    public void init_UnknownDefaultFilter() {
        when(jsfConfigurationMock.getDefaultUserFilter()).thenReturn("xx");
        when(chainManagerMock.getFilter("xx")).thenReturn(null);
        accessDeniedHandler.init();
    }

    @Test
    public void onAccessDenied_notAuthenticated() throws IOException {
        // not authenticated -> redirect
        when(jsfConfigurationMock.getDefaultUserFilter()).thenReturn("user");
        when(chainManagerMock.getFilter("user")).thenReturn(userFilterMock);

        ThreadContext.bind(subjectMock);
        when(subjectMock.getPrincipal()).thenReturn(new Object()); // any value will do
        when(subjectMock.isAuthenticated()).thenReturn(false);

        accessDeniedHandler.init();
        accessDeniedHandler.onAccessDenied(servletRequestMock, servletResponseMock);

        verify(userFilterMock).saveRequestAndRedirectToLogin(servletRequestMock, servletResponseMock);
    }

    @Test
    public void onAccessDenied_authenticated_unauthorizedPage() throws IOException {
        //  authenticated + unauthorizedPage defined -> redirect to unauthorized Page

        ThreadContext.bind(subjectMock);
        when(subjectMock.getPrincipal()).thenReturn(new Object()); // any value will do
        when(subjectMock.isAuthenticated()).thenReturn(true);

        when(jsfConfigurationMock.getUnauthorizedExceptionPage()).thenReturn("/unauthorized.xhtml");
        when(servletResponseMock.encodeRedirectURL("null/unauthorized.xhtml")).thenReturn("null/unauthorized.xhtml");
        accessDeniedHandler.onAccessDenied(servletRequestMock, servletResponseMock);

        verify(servletResponseMock).sendRedirect(urlCaptor.capture());
        assertThat(urlCaptor.getValue()).isEqualTo("null/unauthorized.xhtml");
    }

    @Test
    public void onAccessDenied_authenticated_sendStatus() throws IOException {
        //  authenticated + no unauthorizedPage defined -> send status

        ThreadContext.bind(subjectMock);
        when(subjectMock.getPrincipal()).thenReturn(new Object()); // any value will do
        when(subjectMock.isAuthenticated()).thenReturn(true);

        when(jsfConfigurationMock.getUnauthorizedExceptionPage()).thenReturn("");

        accessDeniedHandler.onAccessDenied(servletRequestMock, servletResponseMock);
        verify(servletResponseMock).sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}