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
package be.atbash.ee.security.octopus.oauth2.google.servlet;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.enterprise.inject.Instance;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class MultipleAccountServletTest {

    @Mock
    private Instance instanceMock;

    @InjectMocks
    private MultipleAccountServlet servlet;

    @Mock
    private HttpServletRequest requestMock;

    @Mock
    private HttpServletResponse responseMock;

    @Mock
    private MultipleAccountContent multipleAccountContentMock;

    @Captor
    private ArgumentCaptor<Cookie> cookieArgumentCaptor;

    @Test
    public void doGet() throws IOException, ServletException {
        // With MultipleAccountContent instance
        when(requestMock.getParameter("value")).thenReturn("true");
        when(instanceMock.isUnsatisfied()).thenReturn(false);
        when(instanceMock.get()).thenReturn(multipleAccountContentMock);

        servlet.doGet(requestMock, responseMock);

        verify(responseMock).addCookie(cookieArgumentCaptor.capture());
        assertThat(cookieArgumentCaptor.getValue().getMaxAge()).isEqualTo(60 * 60 * 24 * 365 * 10);

        verify(multipleAccountContentMock).doGet(requestMock, responseMock);
    }

    @Test
    public void doGet_defaultResponse() throws IOException, ServletException {

        when(requestMock.getParameter("value")).thenReturn("true");
        when(instanceMock.isUnsatisfied()).thenReturn(true);

        StringWriter content = new StringWriter();
        PrintWriter contentWriter = new PrintWriter(content);
        when(responseMock.getWriter()).thenReturn(contentWriter);

        servlet.doGet(requestMock, responseMock);

        verify(responseMock).addCookie(cookieArgumentCaptor.capture());
        assertThat(cookieArgumentCaptor.getValue().getMaxAge()).isEqualTo(60 * 60 * 24 * 365 * 10);

        assertThat(content.toString()).isEqualTo("Octopus : Multiple accounts for Google is active? true");
        verify(multipleAccountContentMock, never()).doGet(requestMock, responseMock);
    }

    @Test
    public void doGet_removeCookie() throws IOException, ServletException {

        when(requestMock.getParameter("value")).thenReturn("false");
        when(instanceMock.isUnsatisfied()).thenReturn(true);

        StringWriter content = new StringWriter();
        PrintWriter contentWriter = new PrintWriter(content);
        when(responseMock.getWriter()).thenReturn(contentWriter);

        servlet.doGet(requestMock, responseMock);

        verify(responseMock).addCookie(cookieArgumentCaptor.capture());
        assertThat(cookieArgumentCaptor.getValue().getMaxAge()).isEqualTo(0);

        assertThat(content.toString()).isEqualTo("Octopus : Multiple accounts for Google is active? false");
        verify(multipleAccountContentMock, never()).doGet(requestMock, responseMock);
    }
}