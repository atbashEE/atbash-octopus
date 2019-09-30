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
package be.atbash.ee.security.octopus.filter;

import be.atbash.ee.security.octopus.WebConstants;
import be.atbash.ee.security.octopus.filter.mgt.FilterChainManager;
import be.atbash.ee.security.octopus.filter.mgt.NamedFilterList;
import be.atbash.ee.security.octopus.util.PatternMatcher;
import be.atbash.util.TestReflectionUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class FilterChainResolverTest {

    @Mock
    private FilterChainManager filterChainManagerMock;

    @Mock
    private PatternMatcher pathMatcherMock;

    @Mock
    private HttpServletRequest servletRequestMock;

    @InjectMocks
    private FilterChainResolver filterChainResolver;

    @Test
    public void getChain_noChains() {

        when(filterChainManagerMock.hasChains()).thenReturn(false);

        FilterChain chain = filterChainResolver.getChain(servletRequestMock, null, null);
        assertThat(chain).isNull();

        verify(filterChainManagerMock).hasChains();
        verifyNoMoreInteractions(filterChainManagerMock);
        verifyNoMoreInteractions(pathMatcherMock);
    }

    @Test
    public void getChain_foundChain() throws NoSuchFieldException {
        FilterChain originalChain = new FilterChain() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse) throws IOException, ServletException {

            }
        };

        when(filterChainManagerMock.hasChains()).thenReturn(true);
        Set<String> chainNames = new HashSet<>();
        chainNames.add("/pages/**");
        chainNames.add("/other/**");
        when(filterChainManagerMock.getChainNames()).thenReturn(chainNames);
        when(servletRequestMock.getContextPath()).thenReturn("/test");
        when(servletRequestMock.getRequestURI()).thenReturn("/test/pages/user.xhtml");
        when(pathMatcherMock.matches("/pages/**", "/pages/user.xhtml")).thenReturn(true);

        when(filterChainManagerMock.proxy(originalChain, "/pages/**")).thenReturn(Mockito.mock(FilterChain.class));

        NamedFilterList namedFilterList = new NamedFilterList("/pages/**");
        TestReflectionUtils.setFieldValue(namedFilterList, "filterNames","The Filter List");
        // Too difficult to generate it under normal conditions in this test.

        when(filterChainManagerMock.getChain("/pages/**")).thenReturn(namedFilterList);

        FilterChain chain = filterChainResolver.getChain(servletRequestMock, null, originalChain);
        assertThat(chain).isNotNull();

        verify(filterChainManagerMock).proxy(originalChain, "/pages/**");
        verify(servletRequestMock).setAttribute(WebConstants.OCTOPUS_CHAIN_NAME, "/pages/**");
        verify(servletRequestMock).setAttribute(WebConstants.OCTOPUS_FILTER_NAMES, "The Filter List");
    }

    @Test
    public void getChain_foundNoChain() {
        FilterChain originalChain = new FilterChain() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse) throws IOException, ServletException {

            }
        };

        when(filterChainManagerMock.hasChains()).thenReturn(true);
        Set<String> chainNames = new HashSet<>();
        chainNames.add("/other/**");
        when(filterChainManagerMock.getChainNames()).thenReturn(chainNames);
        when(servletRequestMock.getContextPath()).thenReturn("/test");
        when(servletRequestMock.getRequestURI()).thenReturn("/test/pages/user.xhtml");

        FilterChain chain = filterChainResolver.getChain(servletRequestMock, null, originalChain);
        assertThat(chain).isNull();

        verify(filterChainManagerMock, never()).proxy(originalChain, "/pages/**");
        verify(filterChainManagerMock).getChainNames();
    }
}