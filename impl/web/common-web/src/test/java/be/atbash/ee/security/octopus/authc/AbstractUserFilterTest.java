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
package be.atbash.ee.security.octopus.authc;

import be.atbash.ee.security.octopus.config.OctopusWebConfiguration;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.session.Session;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.PatternMatcher;
import be.atbash.ee.security.octopus.util.SavedRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class AbstractUserFilterTest {

    @Mock
    private HttpServletRequest requestMock;

    @Mock
    private HttpServletResponse responseMock;

    @Mock
    private PatternMatcher patternMatcherMock;

    @Mock
    private WebSubject subjectMock;

    @Mock
    private OctopusWebConfiguration webConfigurationMock;

    @Mock
    private Session sessionMock;

    @Captor
    private ArgumentCaptor<String> stringCaptor;

    @Captor
    private ArgumentCaptor<SavedRequest> savedRequestCaptor;

    @InjectMocks
    private TestUserFilter userFilter;

    @Test
    public void isAccessAllowed_loginRequest() {
        configureIsLoginRequest(true);

        boolean allowed = userFilter.isAccessAllowed(requestMock, responseMock, null);
        assertThat(allowed).isTrue();
    }

    @Test
    public void isAccessAllowed_noLoginRequest_anonymousUser() {
        configureIsLoginRequest(false);
        ThreadContext.bind(subjectMock);
        when(subjectMock.getPrincipal()).thenReturn(new Object()); // We just need to return something
        when(subjectMock.isAuthenticated()).thenReturn(false);

        boolean allowed = userFilter.isAccessAllowed(requestMock, responseMock, null);
        assertThat(allowed).isFalse();
    }

    @Test
    public void isAccessAllowed_noLoginRequest_authenticatedUser() {
        configureIsLoginRequest(false);
        ThreadContext.bind(subjectMock);
        when(subjectMock.getPrincipal()).thenReturn(new Object()); // We just need to return something
        when(subjectMock.isAuthenticated()).thenReturn(true);

        boolean allowed = userFilter.isAccessAllowed(requestMock, responseMock, null);
        assertThat(allowed).isTrue();
    }

    @Test
    public void onAccessDenied_GET_NoAjax() throws Exception {
        userFilter.setLoginUrl("/login.page");
        when(requestMock.getMethod()).thenReturn("GET");
        when(requestMock.getRequestURI()).thenReturn("/original.page");
        when(requestMock.getContextPath()).thenReturn("/test");
        ThreadContext.bind(subjectMock);  // Required for save request
        when(subjectMock.getSession()).thenReturn(sessionMock);
        when(responseMock.encodeRedirectURL("/test/login.page")).thenReturn("/test/login.page");

        userFilter.onAccessDenied(requestMock, responseMock);

        verify(responseMock).sendRedirect(stringCaptor.capture());
        assertThat(stringCaptor.getValue()).isEqualTo("/test/login.page");

        verify(sessionMock).setAttribute(stringCaptor.capture(), savedRequestCaptor.capture());
        assertThat(savedRequestCaptor.getValue().getRequestUrl()).isEqualTo("/original.page");
        assertThat(savedRequestCaptor.getValue().getMethod()).isEqualTo("GET");
    }

    // FIXME Test GET with AJAX

    @Test
    public void onAccessDenied_POST_postAllowed() throws Exception {
        when(webConfigurationMock.getPostIsAllowedSavedRequest()).thenReturn(true);
        userFilter.setLoginUrl("/login.page");
        when(requestMock.getMethod()).thenReturn("POST");
        when(requestMock.getRequestURI()).thenReturn("/original.page");
        when(requestMock.getContextPath()).thenReturn("/test");
        ThreadContext.bind(subjectMock);  // Required for save request
        when(subjectMock.getSession()).thenReturn(sessionMock);
        when(responseMock.encodeRedirectURL("/test/login.page")).thenReturn("/test/login.page");

        userFilter.onAccessDenied(requestMock, responseMock);

        verify(responseMock).sendRedirect(stringCaptor.capture());
        assertThat(stringCaptor.getValue()).isEqualTo("/test/login.page");

        verify(sessionMock).setAttribute(stringCaptor.capture(), savedRequestCaptor.capture());
        assertThat(savedRequestCaptor.getValue().getRequestUrl()).isEqualTo("/original.page");
        assertThat(savedRequestCaptor.getValue().getMethod()).isEqualTo("POST");
    }

    @Test
    public void onAccessDenied_POST_postNotAllowed() throws Exception {
        when(webConfigurationMock.getPostIsAllowedSavedRequest()).thenReturn(false);
        userFilter.setLoginUrl("/login.page");
        when(requestMock.getMethod()).thenReturn("POST");
        when(requestMock.getContextPath()).thenReturn("/test");
        ThreadContext.bind(subjectMock);  // Required for save request

        when(responseMock.encodeRedirectURL("/test/login.page")).thenReturn("/test/login.page");

        userFilter.onAccessDenied(requestMock, responseMock);

        verify(responseMock).sendRedirect(stringCaptor.capture());
        assertThat(stringCaptor.getValue()).isEqualTo("/test/login.page");

        verify(subjectMock, never()).getSession();
        verify(sessionMock, never()).setAttribute(any(String.class), any(SavedRequest.class));
    }

    @Test
    public void isLoginRequest() {
        configureIsLoginRequest(true);

        assertThat(userFilter.isPrepareLoginCalled()).isFalse();

        boolean loginRequest = userFilter.isLoginRequest(requestMock);
        assertThat(loginRequest).isTrue();
        assertThat(userFilter.isPrepareLoginCalled()).isTrue();
    }

    private void configureIsLoginRequest(boolean isLogin) {
        when(requestMock.getContextPath()).thenReturn("/test");
        when(requestMock.getRequestURI()).thenReturn("/test/login.xhtml");

        when(patternMatcherMock.matches("/login.xhtml", "/login.xhtml")).thenReturn(isLogin);
        userFilter.setLoginUrl("/login.xhtml");
    }

    public static class TestUserFilter extends AbstractUserFilter {

        private boolean prepareLoginCalled = false;

        @Override
        protected void setLoginUrl(String loginUrl) {
            super.setLoginUrl(loginUrl);
        }

        @Override
        protected void prepareLoginURL(ServletRequest request) {
            prepareLoginCalled = true;
        }

        public boolean isPrepareLoginCalled() {
            return prepareLoginCalled;
        }
    }
}