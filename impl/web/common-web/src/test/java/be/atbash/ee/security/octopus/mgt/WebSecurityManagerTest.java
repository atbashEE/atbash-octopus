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
package be.atbash.ee.security.octopus.mgt;

import be.atbash.ee.security.octopus.authc.AfterSuccessfulLoginHandler;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.context.OctopusSecurityContext;
import be.atbash.ee.security.octopus.context.TestSecurityContext;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.realm.OctopusRealm;
import be.atbash.ee.security.octopus.realm.remember.RememberMeManager;
import be.atbash.ee.security.octopus.realm.remember.RememberMeManagerProvider;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.subject.support.WebSubjectContext;
import be.atbash.ee.security.octopus.systemaccount.internal.SystemAccountPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import be.atbash.ee.security.octopus.twostep.TwoStepManager;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.TestReflectionUtils;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class WebSecurityManagerTest {

    @Mock
    private OctopusRealm octopusRealmMock;

    @Mock
    private TwoStepManager twoStepManagerMock;

    @Mock
    private WebSubjectFactory webSubjectFactoryMock;

    @Mock
    private WebSubject webSubjectMock;

    @Mock
    private WebSubject newWebSubjectMock;

    @Mock
    private HttpServletRequest servletRequestMock;

    @Mock
    private HttpServletResponse servletResponseMock;

    @Mock
    private DefaultSubjectDAO subjectDAOMock;

    @Mock
    private AfterSuccessfulLoginHandler successfulLoginHandlerMock;

    @Mock
    private RememberMeManagerProvider rememberMeManagerProviderMock;

    @Mock
    private RememberMeManager rememberMeManagerMock;

    @Captor
    private ArgumentCaptor<Subject> subjectArgument;

    @Captor
    private ArgumentCaptor<WebSubject> webSubjectArgument;

    @Captor
    private ArgumentCaptor<AuthenticationToken> authenticationTokenArgument;

    @Captor
    private ArgumentCaptor<AuthenticationException> authenticationExceptionArgument;

    @Captor
    private ArgumentCaptor<AuthenticationInfo> authenticationInfoArgument;

    @Captor
    private ArgumentCaptor<WebSubjectContext> webSubjectContextArgument;

    private BeanManagerFake beanManagerFake = new BeanManagerFake();

    @InjectMocks
    private WebSecurityManager webSecurityManager;

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void login_success() {
        AuthenticationToken token = new UsernamePasswordToken("JUnit", "secret".toCharArray());

        AuthenticationInfo info = new AuthenticationInfoBuilder()
                .principalId(1L)
                .userName("JUnit")
                .password("secret".toCharArray())
                .build();

        when(twoStepManagerMock.isTwoStepRequired()).thenReturn(false);

        when(octopusRealmMock.authenticate(token)).thenReturn(info);

        when(webSubjectMock.getServletRequest()).thenReturn(servletRequestMock);
        when(webSubjectMock.getServletResponse()).thenReturn(servletResponseMock);

        when(webSubjectFactoryMock.createSubject(any(WebSubjectContext.class))).thenReturn(newWebSubjectMock);
        when(newWebSubjectMock.isAuthenticated()).thenReturn(true);

        beanManagerFake.registerBean(successfulLoginHandlerMock, AfterSuccessfulLoginHandler.class);
        beanManagerFake.endRegistration();

        when(rememberMeManagerProviderMock.getRememberMeManager()).thenReturn(rememberMeManagerMock);

        // test
        webSecurityManager.login(webSubjectMock, token);

        // Checks
        verify(subjectDAOMock).save(newWebSubjectMock);
        verify(twoStepManagerMock, never()).startSecondStep(any(WebSubject.class));
        verify(successfulLoginHandlerMock).onSuccessfulLogin(token, info, newWebSubjectMock);
        verify(rememberMeManagerMock).onSuccessfulLogin(newWebSubjectMock, token, info);
        verify(rememberMeManagerMock, never()).onFailedLogin(any(Subject.class), any(AuthenticationToken.class), any(AuthenticationException.class));

        verify(webSubjectFactoryMock).createSubject(webSubjectContextArgument.capture());
        assertThat(webSubjectContextArgument.getValue().isAuthenticated()).isTrue();

        verify(newWebSubjectMock).endTwoStepProcess();
        verify(newWebSubjectMock, never()).startTwoStepProcess();
        verify(twoStepManagerMock, never()).startSecondStep(newWebSubjectMock);

    }

    @Test(expected = AuthenticationException.class)
    public void login_failure() {
        AuthenticationToken token = new UsernamePasswordToken("JUnit", "secret".toCharArray());

        AuthenticationInfo info = new AuthenticationInfoBuilder()
                .principalId(1L)
                .userName("JUnit")
                .password("secret".toCharArray())
                .build();

        when(octopusRealmMock.authenticate(token)).thenThrow(AuthenticationException.class);

        when(rememberMeManagerProviderMock.getRememberMeManager()).thenReturn(rememberMeManagerMock);

        // test
        try {
            webSecurityManager.login(webSubjectMock, token);
        } finally {
            // Checks
            verify(subjectDAOMock, never()).save(newWebSubjectMock);
            verify(twoStepManagerMock, never()).startSecondStep(any(WebSubject.class));
            verify(successfulLoginHandlerMock, never()).onSuccessfulLogin(token, info, newWebSubjectMock);
            verify(rememberMeManagerMock).onFailedLogin(subjectArgument.capture(), authenticationTokenArgument.capture(), authenticationExceptionArgument.capture());
            assertThat(subjectArgument.getValue()).isSameAs(webSubjectMock);
        }
    }

    @Test
    public void login_systemAccount() throws NoSuchFieldException {

        String identifier = "account1";

        AuthenticationInfo info = new AuthenticationInfoBuilder()
                .principalId(identifier)
                .userPrincipal(new SystemAccountPrincipal(identifier))
                .build();
        when(octopusRealmMock.authenticate(any(AuthenticationToken.class))).thenReturn(info);

        Subject webSubject = new WebSubject(webSecurityManager);
        ThreadContext.bind(webSubject);

        // Not really realistic, map look at a an alternative for WebSubject(webSecurityManager) thje the SubjectContext?
        TestReflectionUtils.setFieldValue(webSubject, "servletRequest", servletRequestMock);
        TestReflectionUtils.setFieldValue(webSubject, "servletResponse", servletResponseMock);

        when(webSubjectFactoryMock.createSubject(any(WebSubjectContext.class))).thenReturn(newWebSubjectMock);
        when(newWebSubjectMock.isAuthenticated()).thenReturn(true);
        when(newWebSubjectMock.getPrincipals()).thenReturn(new PrincipalCollection(new SystemAccountPrincipal(identifier)));

        OctopusSecurityContext securityContext = new TestSecurityContext();

        // test
        securityContext.activateSystemAccount(identifier);

        // Checks

        verify(subjectDAOMock).save(newWebSubjectMock);
        verify(twoStepManagerMock, never()).startSecondStep(any(WebSubject.class));
        verify(successfulLoginHandlerMock, never()).onSuccessfulLogin(any(AuthenticationToken.class), any(AuthenticationInfo.class), any(WebSubject.class));
        verify(rememberMeManagerMock, never()).onSuccessfulLogin(any(WebSubject.class), any(AuthenticationToken.class), any(AuthenticationInfo.class));

        verify(rememberMeManagerMock, never()).onFailedLogin(any(Subject.class), any(AuthenticationToken.class), any(AuthenticationException.class));
        verify(newWebSubjectMock).endTwoStepProcess();
        verify(newWebSubjectMock, never()).startTwoStepProcess();
        verify(twoStepManagerMock, never()).startSecondStep(newWebSubjectMock);

    }

    @Test
    public void login_success_twoStepRequired() {
        AuthenticationToken token = new UsernamePasswordToken("JUnit", "secret".toCharArray());

        AuthenticationInfo info = new AuthenticationInfoBuilder()
                .principalId(1L)
                .userName("JUnit")
                .password("secret".toCharArray())
                .build();

        when(twoStepManagerMock.isTwoStepRequired()).thenReturn(false);

        when(octopusRealmMock.authenticate(token)).thenReturn(info);

        when(webSubjectMock.getServletRequest()).thenReturn(servletRequestMock);
        when(webSubjectMock.getServletResponse()).thenReturn(servletResponseMock);

        when(webSubjectFactoryMock.createSubject(any(WebSubjectContext.class))).thenReturn(newWebSubjectMock);
        when(newWebSubjectMock.isAuthenticated()).thenReturn(false);

        when(twoStepManagerMock.isTwoStepRequired()).thenReturn(true);

        beanManagerFake.registerBean(successfulLoginHandlerMock, AfterSuccessfulLoginHandler.class);
        beanManagerFake.endRegistration();

        // test
        webSecurityManager.login(webSubjectMock, token);

        // Checks
        verify(subjectDAOMock).save(newWebSubjectMock);
        verify(successfulLoginHandlerMock, never()).onSuccessfulLogin(token, info, newWebSubjectMock);
        verify(rememberMeManagerMock, never()).onSuccessfulLogin(newWebSubjectMock, token, info);
        verify(rememberMeManagerMock, never()).onFailedLogin(any(Subject.class), any(AuthenticationToken.class), any(AuthenticationException.class));

        verify(webSubjectFactoryMock).createSubject(webSubjectContextArgument.capture());
        assertThat(webSubjectContextArgument.getValue().isAuthenticated()).isFalse();

        verify(newWebSubjectMock).startTwoStepProcess();
        verify(twoStepManagerMock).startSecondStep(newWebSubjectMock);

    }
}