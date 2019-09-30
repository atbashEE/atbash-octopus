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
package be.atbash.ee.security.octopus.web.servlet;

import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.filter.FilterChainResolver;
import be.atbash.ee.security.octopus.mgt.WebSecurityManager;
import be.atbash.ee.security.octopus.realm.OctopusRealm;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.subject.support.WebSubjectContext;
import be.atbash.ee.security.octopus.web.url.SecuredURLReader;
import be.atbash.util.BeanManagerFake;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OctopusFilterTest {

    @Mock
    private HttpServletRequest servletRequestMock;

    @Mock
    private HttpServletResponse servletResponseMock;

    @Mock
    private FilterChain filterChainMock;

    @Mock
    private FilterChain filterChainResultMock;

    @Mock
    private WebSecurityManager securityManagerMock;

    @Mock
    private FilterChainResolver filterChainResolverMock;

    @Mock
    private SecuredURLReader securedURLReaderMock;

    @Mock
    private OctopusRealm realmMock;

    @Mock
    private FilterConfig filterConfigMock;

    @Mock
    private OctopusCoreConfiguration coreConfigurationMock;

    @Captor
    private ArgumentCaptor<WebSubjectContext> webSubjectContextArgumentCaptor;

    @InjectMocks
    private OctopusFilter filter;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(realmMock, OctopusRealm.class);
        beanManagerFake.endRegistration();

        when(coreConfigurationMock.showDebugFor()).thenReturn(new ArrayList<Debug>());
    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void doFilterInternal() throws ServletException, IOException {

        when(securityManagerMock.createSubject(any(WebSubjectContext.class))).thenReturn(new WebSubject(securityManagerMock));

        // Check if doFilterInternal creates the subject and calls the chain.
        filter.doFilterInternal(servletRequestMock, servletResponseMock, filterChainMock);

        verify(securityManagerMock).createSubject(webSubjectContextArgumentCaptor.capture());

        WebSubjectContext context = webSubjectContextArgumentCaptor.getValue();
        assertThat(context.keySet()).hasSize(3);
        String prefix = WebSubjectContext.class.getName();
        assertThat(context.keySet()).containsOnly(prefix + ".SERVLET_REQUEST", prefix + ".SERVLET_RESPONSE", prefix + ".SECURITY_MANAGER");

        verify(filterChainResolverMock).getChain(servletRequestMock, servletResponseMock, filterChainMock);

    }

    @Test
    public void doFilterInternal_WrappedException() throws IOException {

        when(securityManagerMock.createSubject(any(WebSubjectContext.class))).thenThrow(new NullPointerException());
        try {
            filter.doFilterInternal(servletRequestMock, servletResponseMock, filterChainMock);
            fail("Expected exception not thrown");
        } catch (ServletException ex) {
            assertThat(ex.getRootCause()).isInstanceOf(NullPointerException.class);
        } finally {
            verify(filterChainResolverMock, never()).getChain(servletRequestMock, servletResponseMock, filterChainMock);

        }
    }

    @Test
    public void doFilterInternal_IOException() throws ServletException, IOException {

        when(securityManagerMock.createSubject(any(WebSubjectContext.class))).thenReturn(new WebSubject(securityManagerMock));
        when(filterChainResolverMock.getChain(servletRequestMock, servletResponseMock, filterChainMock)).thenReturn(filterChainResultMock);
        doThrow(new IOException("Message")).when(filterChainResultMock).doFilter(servletRequestMock, servletResponseMock);

        try {
            filter.doFilterInternal(servletRequestMock, servletResponseMock, filterChainMock);
            fail("Expected exception not thrown");
        } catch (IOException ex) {
            assertThat(ex.getMessage()).isEqualTo("Message");
        }
    }

    @Test
    public void init() throws ServletException {
        filter.init(filterConfigMock);

        verify(securedURLReaderMock).loadData(null);  // null as no mock result defined for filterConfig.getServletContext
    }

    @Test
    public void executeChain() throws IOException, ServletException {
        // See that resolved chain got executed.
        when(filterChainResolverMock.getChain(servletRequestMock, servletResponseMock, filterChainMock)).thenReturn(filterChainResultMock);

        filter.executeChain(servletRequestMock, servletResponseMock, filterChainMock);

        verify(filterChainResultMock).doFilter(servletRequestMock, servletResponseMock);
    }

    @Test
    public void executeChain_returnOriginal() throws IOException, ServletException {
        // See that original chain got executed when no resolved one is found.
        when(filterChainResolverMock.getChain(servletRequestMock, servletResponseMock, filterChainMock)).thenReturn(null);

        filter.executeChain(servletRequestMock, servletResponseMock, filterChainMock);

        verify(filterChainMock).doFilter(servletRequestMock, servletResponseMock);
    }

}