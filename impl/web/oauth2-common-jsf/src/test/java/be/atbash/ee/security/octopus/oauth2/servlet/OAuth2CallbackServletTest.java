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
package be.atbash.ee.security.octopus.oauth2.servlet;

import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderMetaData;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderMetaDataControl;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 *
 */
@ExtendWith(MockitoExtension.class)
public class OAuth2CallbackServletTest {

    @Mock
    private OAuth2ServletInfo oauth2ServletInfoMock;

    @Mock
    private OAuth2ProviderMetaDataControl oAuth2ProviderMetaDataControlMock;

    @InjectMocks
    private OAuth2CallbackServlet callbackServlet;

    @Mock
    private HttpServletRequest requestMock;

    @Mock
    private HttpServletResponse responseMock;

    @Mock
    private OAuth2CallbackProcessor processorMock;

    private BeanManagerFake beanManagerFake = new BeanManagerFake();

    private TestLogger logger = TestLoggerFactory.getTestLogger(OAuth2CallbackProcessorTest.DummyOAuth2CallbackProcessor.class);

    @AfterEach
    public void teardown() {
        TestLoggerFactory.clear();

        beanManagerFake.deregistration();
    }

    @Test
    public void doGet() throws IOException, ServletException {
        // only single provider
        List<String> providers = new ArrayList<>();
        providers.add("dummy");
        when(oauth2ServletInfoMock.getProviders()).thenReturn(providers);

        beanManagerFake.registerBean(processorMock, OAuth2CallbackProcessor.class);
        beanManagerFake.endRegistration();

        callbackServlet.doGet(requestMock, responseMock);

        verify(processorMock).processCallback(requestMock, responseMock);

        assertThat(logger.getLoggingEvents()).isEmpty();
        verify(requestMock, never()).getRequestDispatcher(anyString());
        verify(responseMock, never()).reset();
    }

    @Test
    public void doGet_multiple() throws IOException, ServletException {
        // multiple provider
        List<String> providers = new ArrayList<>();
        providers.add("dummy1");
        providers.add("dummy2");
        when(oauth2ServletInfoMock.getProviders()).thenReturn(providers);

        when(oauth2ServletInfoMock.getSelection()).thenReturn("dummy2");
        OAuth2ProviderMetaData metadata = new OAuth2ProviderMetaData() {
            @Override
            public String getServletPath() {
                return null;
            }

            @Override
            public String getName() {
                return "dummy2";
            }

            @Override
            public Class<? extends OAuth2CallbackProcessor> getCallbackProcessor() {
                return DummyCallbackProcessor.class;
            }
        };
        when(oAuth2ProviderMetaDataControlMock.getProviderMetaData("dummy2")).thenReturn(metadata);

        beanManagerFake.registerBean(processorMock, DummyCallbackProcessor.class);
        beanManagerFake.endRegistration();

        callbackServlet.doGet(requestMock, responseMock);

        verify(processorMock).processCallback(requestMock, responseMock);

        assertThat(logger.getLoggingEvents()).isEmpty();
        verify(requestMock, never()).getRequestDispatcher(anyString());
        verify(responseMock, never()).reset();
    }

    public abstract static class DummyCallbackProcessor extends OAuth2CallbackProcessor {

    }
}