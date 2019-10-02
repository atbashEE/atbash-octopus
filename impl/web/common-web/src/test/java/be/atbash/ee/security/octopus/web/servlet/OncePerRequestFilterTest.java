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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class OncePerRequestFilterTest {

    private static final String EXCEPTION_MESSAGE = "doFilterInternal Exception message";

    @Mock
    private HttpServletRequest servletRequestMock;

    @Mock
    private HttpServletResponse servletResponseMock;

    @Mock
    private FilterChain filterChainMock;

    @Captor
    private ArgumentCaptor<String> filteredName;

    private OncePerRequestFilter filter;

    private boolean throwException;

    private boolean filterMethodCalled;

    private String filterName = "JUnit";
    private String filterAttributeName;

    private String attributeName;


    @Before
    public void setup() {
        filter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
                filterMethodCalled = true;
                if (throwException) {
                    throw new ServletException(EXCEPTION_MESSAGE);
                }
            }
        };

        filterMethodCalled = false;
        attributeName = OncePerRequestFilterTest.class.getName() + "$1.FILTERED";

        filterAttributeName = filterName + ".FILTERED";
    }


    @Test
    public void doFilter() throws ServletException, IOException {

        throwException = false;
        filter.setName(filterName);

        filter.doFilter(servletRequestMock, servletResponseMock, filterChainMock);

        // There is an important order. First we need to setAttribute, call method, remove attribute

        InOrder order = Mockito.inOrder(servletRequestMock, filterChainMock);

        order.verify(servletRequestMock).getAttribute(filterAttributeName);
        order.verify(servletRequestMock).setAttribute(filterAttributeName, Boolean.TRUE);
        // Never because we have an overriden definition which just logs
        order.verify(filterChainMock, never()).doFilter(servletRequestMock, null);
        order.verify(servletRequestMock).removeAttribute(filterAttributeName);

        assertThat(filterMethodCalled).isTrue();
        Mockito.verify(servletRequestMock).getAttribute(filterName + ".DISABLED_FOR_REQUEST");

        Mockito.verifyNoMoreInteractions(servletRequestMock, filterChainMock);
    }

    @Test
    public void doFilter_noName() throws ServletException, IOException {

        throwException = false;

        filter.doFilter(servletRequestMock, servletResponseMock, filterChainMock);

        // There is an important order. First we need to setAttribute, call method, remove attribute

        InOrder order = Mockito.inOrder(servletRequestMock, filterChainMock);

        order.verify(servletRequestMock).getAttribute(attributeName);
        order.verify(servletRequestMock).setAttribute(attributeName, Boolean.TRUE);
        // Never because we have an overriden definition which just logs
        order.verify(filterChainMock, never()).doFilter(servletRequestMock, null);
        order.verify(servletRequestMock).removeAttribute(attributeName);

        assertThat(filterMethodCalled).isTrue();
        Mockito.verify(servletRequestMock).getAttribute(filter.getClass().getName() + ".DISABLED_FOR_REQUEST");

        Mockito.verifyNoMoreInteractions(servletRequestMock, filterChainMock);

    }

    @Test
    public void doFilter_Exception() throws IOException {

        throwException = true;

        try {
            filter.doFilter(servletRequestMock, servletResponseMock, null);
            Assert.fail("Should throw ServletException");
        } catch (ServletException e) {
            assertThat(e.getMessage()).isEqualTo(EXCEPTION_MESSAGE);
        }
    }

    @Test
    public void doFilter_alreadyFiltered() throws ServletException, IOException {

        filter.setName(filterName);
        when(servletRequestMock.getAttribute(filterAttributeName)).thenReturn(Boolean.TRUE);

        filter.doFilter(servletRequestMock, null, filterChainMock);

        Mockito.verify(servletRequestMock).getAttribute(filterAttributeName);

        verify(filterChainMock).doFilter(servletRequestMock, null);
        Mockito.verifyNoMoreInteractions(servletRequestMock, filterChainMock);
    }

    @Test
    public void isEnabled_Default() throws ServletException, IOException {
        filter.setName(filterName);
        when(servletRequestMock.getAttribute(filterName + ".DISABLED_FOR_REQUEST")).thenReturn(null); // any return will trigger isEnabled false
        assertThat(filter.isEnabled(servletRequestMock)).isTrue(); //

    }

    @Test
    public void doFilter_disabled() throws ServletException, IOException {

        filter.setName(filterName);
        when(servletRequestMock.getAttribute(filterName + ".DISABLED_FOR_REQUEST")).thenReturn(new Object()); // any return will do

        filter.doFilter(servletRequestMock, null, filterChainMock);

        Mockito.verify(filterChainMock).doFilter(servletRequestMock, null);
        assertThat(filterMethodCalled).isFalse();

        Mockito.verify(servletRequestMock).getAttribute(filterAttributeName);
        Mockito.verify(servletRequestMock).getAttribute(filterName + ".DISABLED_FOR_REQUEST");
        Mockito.verifyNoMoreInteractions(servletRequestMock, filterChainMock);
    }

}
