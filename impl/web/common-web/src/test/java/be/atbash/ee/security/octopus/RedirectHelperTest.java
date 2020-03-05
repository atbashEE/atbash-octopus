/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus;

import be.atbash.config.test.TestConfig;
import be.atbash.util.TestReflectionUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class RedirectHelperTest {

    @Mock
    private HttpServletRequest servletRequestMock;

    @Mock
    private HttpServletResponse servletResponseMock;

    @AfterEach
    public void teardown() throws NoSuchFieldException {
        TestConfig.resetConfig();
        // Reset instance so that initialization happen again.
        TestReflectionUtils.resetOf(RedirectHelper.class, "INSTANCE");
    }

    @Test
    public void testSendRedirect() throws IOException {
        // So that encodeRedirectURL just returns the URL (as no encoding required but want to parameter as return value.
        when(servletResponseMock.encodeRedirectURL(anyString())).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                return invocation.getArgument(0);
            }
        });

        RedirectHelper.getInstance().sendRedirect(servletRequestMock, servletResponseMock, "redirectURL");
        verify(servletResponseMock).sendRedirect("redirectURL");
        verify(servletResponseMock, never()).setStatus(303);

        verify(servletRequestMock, never()).getContextPath();
    }

    @Test
    public void testSendRedirect_http10CompatibleConfig() throws IOException {
        TestConfig.addConfigValue("redirect.http10.compatible", "false");

        // So that encodeRedirectURL just returns the URL (as no encoding required but want to parameter as return value.
        when(servletResponseMock.encodeRedirectURL(anyString())).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                return invocation.getArgument(0);
            }
        });

        RedirectHelper.getInstance().sendRedirect(servletRequestMock, servletResponseMock, "redirectURL");
        verify(servletResponseMock, never()).sendRedirect("redirectURL");
        verify(servletResponseMock).setStatus(303);
        verify(servletResponseMock).setHeader("Location", "redirectURL");

        verify(servletRequestMock, never()).getContextPath();
    }

    @Test
    public void testSendRedirect_contextRoot() throws IOException {
        // So that encodeRedirectURL just returns the URL (as no encoding required but want to parameter as return value.
        when(servletResponseMock.encodeRedirectURL(anyString())).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                return invocation.getArgument(0);
            }
        });

        when(servletRequestMock.getContextPath()).thenReturn("root");  // But not used here
        when(servletRequestMock.getAttribute(WebConstants.REDIRECT_CONTEXT_RELATIVE)).thenReturn(Boolean.TRUE);

        RedirectHelper.getInstance().sendRedirect(servletRequestMock, servletResponseMock, "/redirectURL");
        verify(servletResponseMock).sendRedirect("root/redirectURL");
        verify(servletResponseMock, never()).setStatus(303);
    }

    @Test
    public void testSendRedirect_noContextRoot_notStartingWithSlash() throws IOException {
        // So that encodeRedirectURL just returns the URL (as no encoding required but want to parameter as return value.
        when(servletResponseMock.encodeRedirectURL(anyString())).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                return invocation.getArgument(0);
            }
        });

        when(servletRequestMock.getAttribute(WebConstants.REDIRECT_CONTEXT_RELATIVE)).thenReturn(Boolean.TRUE);

        RedirectHelper.getInstance().sendRedirect(servletRequestMock, servletResponseMock, "redirectURL");
        verify(servletResponseMock).sendRedirect("redirectURL");
        verify(servletResponseMock, never()).setStatus(303);

        verify(servletRequestMock, never()).getContextPath();
    }

}