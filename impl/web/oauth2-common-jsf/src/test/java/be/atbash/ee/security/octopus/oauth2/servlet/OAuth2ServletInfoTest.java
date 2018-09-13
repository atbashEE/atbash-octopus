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
package be.atbash.ee.security.octopus.oauth2.servlet;

import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.oauth2.config.jsf.OAuth2JSFConfiguration;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderMetaData;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderMetaDataControl;
import be.atbash.ee.security.octopus.session.Session;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.SavedRequest;
import be.atbash.util.TestReflectionUtils;
import be.atbash.util.exception.AtbashIllegalActionException;
import be.atbash.util.jsf.FakeFacesContext;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.faces.context.ExternalContext;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;


@RunWith(MockitoJUnitRunner.class)
public class OAuth2ServletInfoTest {

    @Mock
    private OAuth2ProviderMetaDataControl oauth2ProviderMetaDataControlMock;

    @Mock
    private OAuth2JSFConfiguration oAuth2ConfigurationMock;

    @InjectMocks
    private OAuth2ServletInfo servletInfo;

    @Mock
    private ExternalContext externalContextMock;

    @Mock
    private WebSubject webSubjectMock;

    @Mock
    private Session sessionMock;

    @Mock
    private HttpServletRequest requestMock;

    @Captor
    private ArgumentCaptor<String> redirectStringCaptor;

    @Test
    public void getServletPath_scenario1() {
        // NO selection, single provider
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(new TestProviderMetaData("test", "/path"));
        when(oauth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        servletInfo.init();

        String servletPath = servletInfo.getServletPath();
        assertThat(servletPath).isEqualTo("/path");

        verifyNoMoreInteractions(oAuth2ConfigurationMock);
    }

    @Test
    public void getServletPath_scenario2() {
        // NO selection, multiple provider
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(new TestProviderMetaData("test1", "/path1"));
        metaDataList.add(new TestProviderMetaData("test2", "/path2"));
        when(oauth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        when(oAuth2ConfigurationMock.getOAuth2ProviderSelectionPage()).thenReturn("/selection");
        servletInfo.init();

        String servletPath = servletInfo.getServletPath();
        assertThat(servletPath).isEqualTo("/selection");
    }

    @Test
    public void getServletPath_scenario3() throws NoSuchFieldException {
        // selection made
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(new TestProviderMetaData("test1", "/path1"));
        metaDataList.add(new TestProviderMetaData("test2", "/path2"));
        when(oauth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        servletInfo.init();
        // We could set this value with authenticateWith() but does a lot more and is tested separately.
        TestReflectionUtils.setFieldValue(servletInfo, "userProviderSelection", "test2");

        String servletPath = servletInfo.getServletPath();
        assertThat(servletPath).isEqualTo("/path2");
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void getServletPath_scenario4() throws NoSuchFieldException {
        // wrong selection is never possible without reflection
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(new TestProviderMetaData("test1", "/path1"));
        metaDataList.add(new TestProviderMetaData("test2", "/path2"));
        when(oauth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        servletInfo.init();
        // We could set this value with authenticateWith() but does a lot more and is tested separately.
        TestReflectionUtils.setFieldValue(servletInfo, "userProviderSelection", "wrong");

        servletInfo.getServletPath();
    }

    @Test
    public void authenticateWith_scenario1() throws NoSuchFieldException, IOException {
        // Existing metadata
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(new TestProviderMetaData("test1", "/path1"));
        metaDataList.add(new TestProviderMetaData("test2", "/path2"));
        when(oauth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        servletInfo.init();
        FakeFacesContext.registerFake(externalContextMock);

        when(requestMock.getRequestURI()).thenReturn("/original");

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getSession(false)).thenReturn(sessionMock);
        when(webSubjectMock.getSession()).thenReturn(sessionMock);
        SavedRequest savedRequest = new SavedRequest(requestMock);
        when(sessionMock.getAttribute("octopusSavedRequest")).thenReturn(savedRequest);


        servletInfo.authenticateWith("test1");
        // Check by reflection if the value is set.
        Object selection = TestReflectionUtils.getValueOf(servletInfo, "userProviderSelection");
        assertThat(selection).isEqualTo("test1");

        // Check if a redirect to the original saved request is made
        verify(externalContextMock).redirect(redirectStringCaptor.capture());
        assertThat(redirectStringCaptor.getValue()).isEqualTo("/original");
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void authenticateWith_scenario2() throws IOException {
        // Wrong metadata provider specified
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(new TestProviderMetaData("test1", "/path1"));
        metaDataList.add(new TestProviderMetaData("test2", "/path2"));
        when(oauth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        servletInfo.init();

        try {
            servletInfo.authenticateWith("wrong");
        } finally {

            // Check if no redirect is made
            verify(externalContextMock, never()).redirect(anyString());
        }
    }

    public static class TestProviderMetaData implements OAuth2ProviderMetaData {

        private String name;
        private String servletPath;

        TestProviderMetaData(String name, String servletPath) {
            this.name = name;
            this.servletPath = servletPath;
        }

        @Override
        public String getServletPath() {
            return servletPath;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public Class<? extends OAuth2CallbackProcessor> getCallbackProcessor() {
            return null;
        }
    }


}