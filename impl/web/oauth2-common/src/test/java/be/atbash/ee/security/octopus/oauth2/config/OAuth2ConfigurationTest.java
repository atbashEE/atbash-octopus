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
package be.atbash.ee.security.octopus.oauth2.config;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderMetaData;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderMetaDataControl;
import be.atbash.ee.security.octopus.oauth2.servlet.OAuth2CallbackProcessor;
import be.atbash.ee.security.octopus.oauth2.servlet.OAuth2ServletInfo;
import be.atbash.util.BeanManagerFake;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2ConfigurationTest {

    @Mock
    private OAuth2ProviderMetaDataControl oAuth2ProviderMetaDataControlMock;

    @Mock
    private OAuth2ServletInfo servletInfoMock;

    @InjectMocks
    private OAuth2Configuration configuration;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() throws IllegalAccessException {

        beanManagerFake = new BeanManagerFake();
    }

    @After
    public void tearDown() {
        TestConfig.resetConfig();
        beanManagerFake.deregistration();
    }

    @Test
    public void getClientId_singleProvider() {
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(new TestOAuth2ProviderMetaData());

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        TestConfig.addConfigValue("OAuth2.clientId", "testClientId");

        String clientId = configuration.getClientId();
        assertThat(clientId).isEqualTo("testClientId");
    }

    @Test(expected = ConfigurationException.class)
    public void getClientId_singleProvider_noValue() {
        TestOAuth2ProviderMetaData providerMetaData = new TestOAuth2ProviderMetaData("test");

        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(providerMetaData);

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);
        when(oAuth2ProviderMetaDataControlMock.getSingleProviderMetaData()).thenReturn(providerMetaData);

        configuration.getClientId();

    }

    @Test
    public void getClientId_singleProvider_providerValue() {
        TestOAuth2ProviderMetaData providerMetaData = new TestOAuth2ProviderMetaData("test");
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(providerMetaData);

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);
        when(oAuth2ProviderMetaDataControlMock.getSingleProviderMetaData()).thenReturn(providerMetaData);

        TestConfig.addConfigValue("test.OAuth2.clientId", "testClientId");

        String clientId = configuration.getClientId();
        assertThat(clientId).isEqualTo("testClientId");
    }

    @Test
    public void getClientId_multipleProvider_noSelection() {
        beanManagerFake.endRegistration();

        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(new TestOAuth2ProviderMetaData("provider1"));
        metaDataList.add(new TestOAuth2ProviderMetaData("provider2"));

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<>();
        parameters.put("provider1.OAuth2.clientId", "testClientId");
        parameters.put("provider2.OAuth2.clientId", "test2ClientId");
        TestConfig.addConfigValues(parameters);

        String clientId = configuration.getClientId();
        assertThat(clientId).isEqualTo("provider1 : testClientId\nprovider2 : test2ClientId\n");
    }

    @Test
    public void getClientId_multipleProvider_withSelection() {
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(new TestOAuth2ProviderMetaData("provider1"));
        metaDataList.add(new TestOAuth2ProviderMetaData("provider2"));

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<>();
        parameters.put("provider1.OAuth2.clientId", "testClientId");
        parameters.put("provider2.OAuth2.clientId", "test2ClientId");
        TestConfig.addConfigValues(parameters);

        beanManagerFake.registerBean(servletInfoMock, OAuth2ServletInfo.class);
        beanManagerFake.endRegistration();
        when(servletInfoMock.getUserProviderSelection()).thenReturn("provider2");

        String clientId = configuration.getClientId();
        assertThat(clientId).isEqualTo("test2ClientId");
    }

    @Test
    public void getClientSecret_singleProvider() {
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<OAuth2ProviderMetaData>();
        metaDataList.add(new TestOAuth2ProviderMetaData());

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        TestConfig.addConfigValue("OAuth2.clientSecret", "testClientSecret");

        String clientSecret = configuration.getClientSecret();
        assertThat(clientSecret).isEqualTo("testClientSecret");
    }

    @Test(expected = ConfigurationException.class)
    public void getClientSecret_singleProvider_noValue() {
        TestOAuth2ProviderMetaData providerMetaData = new TestOAuth2ProviderMetaData("test");

        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(providerMetaData);

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);
        when(oAuth2ProviderMetaDataControlMock.getSingleProviderMetaData()).thenReturn(providerMetaData);

        configuration.getClientSecret();

    }

    @Test
    public void getClientSecret_singleProvider_providerValue() {
        TestOAuth2ProviderMetaData providerMetaData = new TestOAuth2ProviderMetaData("test");
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(providerMetaData);

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);
        when(oAuth2ProviderMetaDataControlMock.getSingleProviderMetaData()).thenReturn(providerMetaData);

        TestConfig.addConfigValue("test.OAuth2.clientSecret", "testClientSecret");

        String clientId = configuration.getClientSecret();
        assertThat(clientId).isEqualTo("testClientSecret");
    }

    @Test
    public void getClientSecret_multipleProvider_noSelection() {
        beanManagerFake.endRegistration();

        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(new TestOAuth2ProviderMetaData("provider1"));
        metaDataList.add(new TestOAuth2ProviderMetaData("provider2"));

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<>();
        parameters.put("provider1.OAuth2.clientSecret", "testClientSecret");
        parameters.put("provider2.OAuth2.clientSecret", "test2ClientSecret");
        TestConfig.addConfigValues(parameters);

        String clientSecret = configuration.getClientSecret();
        assertThat(clientSecret).isEqualTo("provider1 : testClientSecret\nprovider2 : test2ClientSecret\n");
    }

    @Test
    public void getClientSecret_multipleProvider_withSelection() {
        List<OAuth2ProviderMetaData> metaDataList = new ArrayList<>();
        metaDataList.add(new TestOAuth2ProviderMetaData("provider1"));
        metaDataList.add(new TestOAuth2ProviderMetaData("provider2"));

        when(oAuth2ProviderMetaDataControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<>();
        parameters.put("provider1.OAuth2.clientSecret", "testClientSecret");
        parameters.put("provider2.OAuth2.clientSecret", "test2ClientSecret");
        TestConfig.addConfigValues(parameters);

        beanManagerFake.registerBean(servletInfoMock, OAuth2ServletInfo.class);
        beanManagerFake.endRegistration();
        when(servletInfoMock.getUserProviderSelection()).thenReturn("provider2");

        String clientSecret = configuration.getClientSecret();
        assertThat(clientSecret).isEqualTo("test2ClientSecret");
    }

    public static class TestOAuth2ProviderMetaData implements OAuth2ProviderMetaData {

        private String name;
        private String servletPath;

        public TestOAuth2ProviderMetaData() {
            this(null, null);
        }

        public TestOAuth2ProviderMetaData(String name) {
            this(name, null);
        }

        public TestOAuth2ProviderMetaData(String name, String servletPath) {
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

        //@Override
        //public OAuth2InfoProvider getInfoProvider() {
        //    return null;
        //}

        @Override
        public Class<? extends OAuth2CallbackProcessor> getCallbackProcessor() {
            return null;
        }

        //@Override
        //public Class<? extends AbstractOAuth2AuthcFilter> getOAuth2AuthcFilter() {
        //    return null;
        //}
    }

}