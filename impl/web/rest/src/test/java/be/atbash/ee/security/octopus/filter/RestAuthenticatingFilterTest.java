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
package be.atbash.ee.security.octopus.filter;

import be.atbash.ee.security.octopus.authz.UnauthenticatedException;
import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class RestAuthenticatingFilterTest {

    @Mock
    private HttpServletResponse servletResponseMock;

    private RestAuthenticatingFilter filter = new DemoRestFilter();

    @Test
    public void cleanup() throws ServletException, IOException {

        filter.cleanup(null, null, null);

    }

    @Test
    public void cleanup_authorizationException() throws ServletException, IOException {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintWriter writer = new PrintWriter(out);
        when(servletResponseMock.getWriter()).thenReturn(writer);

        ServletException exception = new ServletException(new SecurityAuthorizationViolationException("Not allowed", "some method"));
        filter.cleanup(null, servletResponseMock, exception);

        writer.flush();

        verify(servletResponseMock).reset();
        verify(servletResponseMock).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(servletResponseMock).setHeader("Content-Type", "application/json");

        assertThat(out.toString()).isEqualTo("{\"code\":\"OCT-002\", \"message\":\"Not allowed\"}");

    }

    @Test
    public void cleanup_authenticationException() throws ServletException, IOException {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintWriter writer = new PrintWriter(out);
        when(servletResponseMock.getWriter()).thenReturn(writer);

        ServletException exception = new ServletException(new UnauthenticatedException("Not valid"));
        filter.cleanup(null, servletResponseMock, exception);

        writer.flush();

        verify(servletResponseMock).reset();
        verify(servletResponseMock).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(servletResponseMock).setHeader("Content-Type", "application/json");

        assertThat(out.toString()).isEqualTo("{\"code\":\"OCT-002\", \"message\":\"Not valid\"}");

    }

    @Test
    public void cleanup_OtherException() throws ServletException, IOException {

        NullPointerException exception = new NullPointerException();
        try {
            filter.cleanup(null, servletResponseMock, exception);
            fail("Exception should be thrown");
        } catch (ServletException e) {
            verifyNoMoreInteractions(servletResponseMock);
            // Check if exception is wrapped
            assertThat(e.getRootCause()).isSameAs(exception);
        }

    }

    @Test
    public void cleanup_ServletExceptionJustThrown() throws ServletException, IOException {

        ServletException exception = new ServletException();
        try {
            filter.cleanup(null, servletResponseMock, exception);
            fail("Exception should be thrown");
        } catch (ServletException e) {
            verifyNoMoreInteractions(servletResponseMock);
            // Check if original exception
            assertThat(e).isSameAs(exception);
        }
    }

    @Test
    public void cleanup_IOExceptionJustThrown() throws ServletException, IOException {

        IOException exception = new IOException();
        try {
            filter.cleanup(null, servletResponseMock, exception);
            fail("Exception should be thrown");
        } catch (IOException e) {
            verifyNoMoreInteractions(servletResponseMock);
            // Check if original exception
            assertThat(e).isSameAs(exception);
        }

    }

    private static class DemoRestFilter extends RestAuthenticatingFilter {

        @Override
        protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
            return null;
        }

        @Override
        protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
            return false;
        }
    }
}