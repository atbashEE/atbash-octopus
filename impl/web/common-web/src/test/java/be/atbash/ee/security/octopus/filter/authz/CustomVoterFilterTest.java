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

import be.atbash.ee.security.octopus.authz.permission.voter.AbstractGenericVoter;
import be.atbash.ee.security.octopus.context.internal.OctopusInvocationContext;
import be.atbash.ee.security.octopus.interceptor.CustomAccessDecisionVoterContext;
import be.atbash.util.BeanManagerFake;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.enterprise.inject.UnsatisfiedResolutionException;
import javax.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CustomVoterFilterTest {

    private static final String URL = "/path/to/foo";
    private BeanManagerFake beanManagerFake;

    private CustomVoterFilter filter;

    @Mock
    private AbstractGenericVoter genericVoter1Mock;

    @Mock
    private AbstractGenericVoter genericVoter2Mock;

    @Mock
    private HttpServletRequest servletRequestMock;

    @Captor
    private ArgumentCaptor<AccessDecisionVoterContext> decisionVoterContextArgumentCaptor;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean("custom1", genericVoter1Mock);
        beanManagerFake.registerBean("custom2", genericVoter2Mock);
        beanManagerFake.endRegistration();

        filter = new CustomVoterFilter();

        when(servletRequestMock.getRequestURL()).thenReturn(new StringBuffer(URL));

    }

    @After
    public void cleanup() {
        beanManagerFake.deregistration();
    }

    @Test
    public void isAccessAllowed_allowed() throws Exception {

        when(genericVoter1Mock.verify(any(AccessDecisionVoterContext.class))).thenReturn(true);

        boolean allowed = filter.isAccessAllowed(servletRequestMock, null, new String[]{"custom1"});

        assertThat(allowed).isTrue();

        verify(genericVoter1Mock).verify(decisionVoterContextArgumentCaptor.capture());
        assertThat(decisionVoterContextArgumentCaptor.getValue()).isInstanceOf(CustomAccessDecisionVoterContext.class);

        CustomAccessDecisionVoterContext context = (CustomAccessDecisionVoterContext) decisionVoterContextArgumentCaptor.getValue();
        OctopusInvocationContext invocationContext = context.getSource();
        assertThat(invocationContext.getTarget()).isEqualTo(URL);

        verify(genericVoter1Mock).verify(any(AccessDecisionVoterContext.class));
        verify(genericVoter2Mock, never()).verify(any(AccessDecisionVoterContext.class));
    }

    @Test
    public void isAccessAllowed_notAllowed() throws Exception {

        when(genericVoter1Mock.verify(any(AccessDecisionVoterContext.class))).thenReturn(false);

        boolean allowed = filter.isAccessAllowed(servletRequestMock, null, new String[]{"custom1"});

        assertThat(allowed).isFalse();

        verify(genericVoter1Mock).verify(decisionVoterContextArgumentCaptor.capture());
        assertThat(decisionVoterContextArgumentCaptor.getValue()).isInstanceOf(CustomAccessDecisionVoterContext.class);

        CustomAccessDecisionVoterContext context = (CustomAccessDecisionVoterContext) decisionVoterContextArgumentCaptor.getValue();
        OctopusInvocationContext invocationContext = context.getSource();
        assertThat(invocationContext.getTarget()).isEqualTo(URL);

        verify(genericVoter1Mock).verify(any(AccessDecisionVoterContext.class));
        verify(genericVoter2Mock, never()).verify(any(AccessDecisionVoterContext.class));

    }

    @Test(expected = UnsatisfiedResolutionException.class)
    public void isAccessAllowed_nonExistent() throws Exception {

        try {
            filter.isAccessAllowed(servletRequestMock, null, new String[]{"custom3"});
        } finally {
            verify(genericVoter1Mock, never()).verify(any(AccessDecisionVoterContext.class));
            verify(genericVoter2Mock, never()).verify(any(AccessDecisionVoterContext.class));

        }
    }

    @Test
    public void isAccessAllowed_multiple_allowed() throws Exception {

        when(genericVoter1Mock.verify(any(AccessDecisionVoterContext.class))).thenReturn(true);
        when(genericVoter2Mock.verify(any(AccessDecisionVoterContext.class))).thenReturn(true);

        boolean allowed = filter.isAccessAllowed(servletRequestMock, null, new String[]{"custom1", "custom2"});

        assertThat(allowed).isTrue();

        verify(genericVoter1Mock).verify(decisionVoterContextArgumentCaptor.capture());
        assertThat(decisionVoterContextArgumentCaptor.getValue()).isInstanceOf(CustomAccessDecisionVoterContext.class);

        CustomAccessDecisionVoterContext context = (CustomAccessDecisionVoterContext) decisionVoterContextArgumentCaptor.getValue();
        OctopusInvocationContext invocationContext = context.getSource();
        assertThat(invocationContext.getTarget()).isEqualTo(URL);

        verify(genericVoter1Mock).verify(any(AccessDecisionVoterContext.class));
        verify(genericVoter2Mock).verify(any(AccessDecisionVoterContext.class));

    }

    @Test
    public void isAccessAllowed_multiple_oneNotAllowed() throws Exception {

        when(genericVoter1Mock.verify(any(AccessDecisionVoterContext.class))).thenReturn(true);
        when(genericVoter2Mock.verify(any(AccessDecisionVoterContext.class))).thenReturn(false);

        boolean allowed = filter.isAccessAllowed(servletRequestMock, null, new String[]{"custom1", "custom2"});

        assertThat(allowed).isFalse();

        verify(genericVoter1Mock).verify(decisionVoterContextArgumentCaptor.capture());
        assertThat(decisionVoterContextArgumentCaptor.getValue()).isInstanceOf(CustomAccessDecisionVoterContext.class);

        CustomAccessDecisionVoterContext context = (CustomAccessDecisionVoterContext) decisionVoterContextArgumentCaptor.getValue();
        OctopusInvocationContext invocationContext = context.getSource();
        assertThat(invocationContext.getTarget()).isEqualTo(URL);

        verify(genericVoter1Mock).verify(any(AccessDecisionVoterContext.class));
        verify(genericVoter2Mock).verify(any(AccessDecisionVoterContext.class));

    }
}