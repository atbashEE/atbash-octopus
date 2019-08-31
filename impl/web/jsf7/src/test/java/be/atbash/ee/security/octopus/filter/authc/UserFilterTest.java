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
package be.atbash.ee.security.octopus.filter.authc;

import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.PatternMatcher;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class UserFilterTest {

    @Mock
    private HttpServletRequest requestMock;

    @Mock
    private HttpServletResponse responseMock;

    @Mock
    private WebSubject subjectMock;

    @Mock
    private PatternMatcher patternMatcherMock;

    @InjectMocks
    private TestUserFilter userFilter;

    @Test
    public void isAccessAllowed_loginRequest() {
        configureIsLoginRequest(true);

        boolean allowed = userFilter.isAccessAllowed(requestMock, responseMock);
        assertThat(allowed).isTrue();
    }

    @Test
    public void isAccessAllowed_noLoginRequest_anonymousUser() {
        configureIsLoginRequest(false);
        ThreadContext.bind(subjectMock);
        when(subjectMock.isAuthenticated()).thenReturn(false);
        when(subjectMock.isRemembered()).thenReturn(false);

        boolean allowed = userFilter.isAccessAllowed(requestMock, responseMock);
        assertThat(allowed).isFalse();
    }

    @Test
    public void isAccessAllowed_noLoginRequest_authenticatedUser() {
        configureIsLoginRequest(false);
        ThreadContext.bind(subjectMock);
        when(subjectMock.isAuthenticated()).thenReturn(true);

        boolean allowed = userFilter.isAccessAllowed(requestMock, responseMock);
        assertThat(allowed).isTrue();
    }

    @Test
    public void isAccessAllowed_noLoginRequest_rememberedUser() {
        configureIsLoginRequest(false);
        ThreadContext.bind(subjectMock);
        when(subjectMock.isAuthenticated()).thenReturn(false);
        when(subjectMock.isRemembered()).thenReturn(true);

        boolean allowed = userFilter.isAccessAllowed(requestMock, responseMock);
        assertThat(allowed).isTrue();
    }


    private void configureIsLoginRequest(boolean isLogin) {
        when(requestMock.getContextPath()).thenReturn("/test");
        when(requestMock.getRequestURI()).thenReturn("/test/login.xhtml");

        when(patternMatcherMock.matches("/login.xhtml", "/login.xhtml")).thenReturn(isLogin);
        userFilter.setLoginUrl("/login.xhtml");
    }

    public static class TestUserFilter extends UserFilter {

        @Override
        protected void setLoginUrl(String loginUrl) {
            super.setLoginUrl(loginUrl);
        }

    }

}