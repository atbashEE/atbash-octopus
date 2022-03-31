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
package be.atbash.ee.security.octopus.authz;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;

import static be.atbash.ee.security.octopus.OctopusConstants.OCTOPUS_VIOLATION_MESSAGE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 */
@ExtendWith(MockitoExtension.class)
public class RestAccessDeniedHandlerTest {

    @Mock
    private HttpServletRequest servletRequestMock;

    @Mock
    private HttpServletResponse servletResponseMock;

    @InjectMocks  // Mocks don't need to be injected but then we have already the instantiation :)
    private RestAccessDeniedHandler accessDeniedHandler;

    @Test
    public void onAccessDenied() throws IOException {
        when(servletRequestMock.getAttribute(OCTOPUS_VIOLATION_MESSAGE)).thenReturn("Violation of xyz");

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintWriter writer = new PrintWriter(out);
        when(servletResponseMock.getWriter()).thenReturn(writer);

        boolean result = accessDeniedHandler.onAccessDenied(servletRequestMock, servletResponseMock);
        assertThat(result).isFalse();

        verify(servletResponseMock).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(servletResponseMock).setHeader("Content-Type", "application/json");

        writer.flush();
        assertThat(out.toString()).isEqualTo("{\"code\":\"OCT-002\", \"message\":\"Violation of xyz\"}");

    }

    @Test
    public void onAccessDenied_missingViolationMessage() throws IOException {
        when(servletRequestMock.getAttribute(OCTOPUS_VIOLATION_MESSAGE)).thenReturn(null);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintWriter writer = new PrintWriter(out);
        when(servletResponseMock.getWriter()).thenReturn(writer);

        boolean result = accessDeniedHandler.onAccessDenied(servletRequestMock, servletResponseMock);
        assertThat(result).isFalse();

        verify(servletResponseMock).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(servletResponseMock).setHeader("Content-Type", "application/json");

        writer.flush();
        assertThat(out.toString()).isEqualTo("{\"code\":\"OCT-002\", \"message\":\"Unable to determine the message\"}");

    }
}