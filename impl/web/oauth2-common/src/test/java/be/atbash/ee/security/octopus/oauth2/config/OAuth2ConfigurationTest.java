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
package be.atbash.ee.security.octopus.oauth2.config;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2Provider;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderControl;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class OAuth2ConfigurationTest {

    @Mock
    private OAuth2ProviderControl oAuth2ProviderControlMock;

    @Mock
    private ProviderSelection providerSelectionMock;

    @InjectMocks
    private OAuth2Configuration configuration;

    private BeanManagerFake beanManagerFake;

    @BeforeEach
    public void setup() {

        beanManagerFake = new BeanManagerFake();
    }

    @AfterEach
    public void tearDown() {
        TestConfig.resetConfig();
        beanManagerFake.deregistration();
    }

    @Test
    public void getClientId_singleProvider() {
        List<OAuth2Provider> metaDataList = new ArrayList<>();
        metaDataList.add(new TestOAuth2Provider());

        when(oAuth2ProviderControlMock.getProviderInfos()).thenReturn(metaDataList);

        TestConfig.addConfigValue("OAuth2.clientId", "testClientId");

        String clientId = configuration.getClientId();
        assertThat(clientId).isEqualTo("testClientId");
    }

    @Test
    public void getClientId_singleProvider_noValue() {
        TestOAuth2Provider providerMetaData = new TestOAuth2Provider("test");

        List<OAuth2Provider> metaDataList = new ArrayList<>();
        metaDataList.add(providerMetaData);

        when(oAuth2ProviderControlMock.getProviderInfos()).thenReturn(metaDataList);
        when(oAuth2ProviderControlMock.getSingleProviderMetaData()).thenReturn(providerMetaData);

        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getClientId());

    }

    @Test
    public void getClientId_singleProvider_providerValue() {
        TestOAuth2Provider providerMetaData = new TestOAuth2Provider("test");
        List<OAuth2Provider> metaDataList = new ArrayList<>();
        metaDataList.add(providerMetaData);

        when(oAuth2ProviderControlMock.getProviderInfos()).thenReturn(metaDataList);
        when(oAuth2ProviderControlMock.getSingleProviderMetaData()).thenReturn(providerMetaData);

        TestConfig.addConfigValue("test.OAuth2.clientId", "testClientId");

        String clientId = configuration.getClientId();
        assertThat(clientId).isEqualTo("testClientId");
    }

    @Test
    public void getClientId_multipleProvider_noSelection() {
        beanManagerFake.endRegistration();

        List<OAuth2Provider> metaDataList = new ArrayList<>();
        metaDataList.add(new TestOAuth2Provider("provider1"));
        metaDataList.add(new TestOAuth2Provider("provider2"));

        when(oAuth2ProviderControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<>();
        parameters.put("provider1.OAuth2.clientId", "testClientId");
        parameters.put("provider2.OAuth2.clientId", "test2ClientId");
        TestConfig.addConfigValues(parameters);

        String clientId = configuration.getClientId();
        assertThat(clientId).isEqualTo("provider1 : testClientId\nprovider2 : test2ClientId\n");
    }

    @Test
    public void getClientId_multipleProvider_withSelection() {
        List<OAuth2Provider> metaDataList = new ArrayList<>();
        metaDataList.add(new TestOAuth2Provider("provider1"));
        metaDataList.add(new TestOAuth2Provider("provider2"));

        when(oAuth2ProviderControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<>();
        parameters.put("provider1.OAuth2.clientId", "testClientId");
        parameters.put("provider2.OAuth2.clientId", "test2ClientId");
        TestConfig.addConfigValues(parameters);

        beanManagerFake.registerBean(providerSelectionMock, ProviderSelection.class);
        beanManagerFake.endRegistration();
        when(providerSelectionMock.getProvider()).thenReturn("provider2");

        String clientId = configuration.getClientId();
        assertThat(clientId).isEqualTo("test2ClientId");
    }

    @Test
    public void getClientSecret_singleProvider() {
        List<OAuth2Provider> metaDataList = new ArrayList<OAuth2Provider>();
        metaDataList.add(new TestOAuth2Provider());

        when(oAuth2ProviderControlMock.getProviderInfos()).thenReturn(metaDataList);

        TestConfig.addConfigValue("OAuth2.clientSecret", "testClientSecret");

        String clientSecret = configuration.getClientSecret();
        assertThat(clientSecret).isEqualTo("testClientSecret");
    }

    @Test
    public void getClientSecret_singleProvider_noValue() {
        TestOAuth2Provider providerMetaData = new TestOAuth2Provider("test");

        List<OAuth2Provider> metaDataList = new ArrayList<>();
        metaDataList.add(providerMetaData);

        when(oAuth2ProviderControlMock.getProviderInfos()).thenReturn(metaDataList);
        when(oAuth2ProviderControlMock.getSingleProviderMetaData()).thenReturn(providerMetaData);

        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getClientSecret());

    }

    @Test
    public void getClientSecret_singleProvider_providerValue() {
        TestOAuth2Provider providerMetaData = new TestOAuth2Provider("test");
        List<OAuth2Provider> metaDataList = new ArrayList<>();
        metaDataList.add(providerMetaData);

        when(oAuth2ProviderControlMock.getProviderInfos()).thenReturn(metaDataList);
        when(oAuth2ProviderControlMock.getSingleProviderMetaData()).thenReturn(providerMetaData);

        TestConfig.addConfigValue("test.OAuth2.clientSecret", "testClientSecret");

        String clientId = configuration.getClientSecret();
        assertThat(clientId).isEqualTo("testClientSecret");
    }

    @Test
    public void getClientSecret_multipleProvider_noSelection() {
        beanManagerFake.endRegistration();

        List<OAuth2Provider> metaDataList = new ArrayList<>();
        metaDataList.add(new TestOAuth2Provider("provider1"));
        metaDataList.add(new TestOAuth2Provider("provider2"));

        when(oAuth2ProviderControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<>();
        parameters.put("provider1.OAuth2.clientSecret", "testClientSecret");
        parameters.put("provider2.OAuth2.clientSecret", "test2ClientSecret");
        TestConfig.addConfigValues(parameters);

        String clientSecret = configuration.getClientSecret();
        assertThat(clientSecret).isEqualTo("provider1 : testClientSecret\nprovider2 : test2ClientSecret\n");
    }

    @Test
    public void getClientSecret_multipleProvider_withSelection() {
        List<OAuth2Provider> metaDataList = new ArrayList<>();
        metaDataList.add(new TestOAuth2Provider("provider1"));
        metaDataList.add(new TestOAuth2Provider("provider2"));

        when(oAuth2ProviderControlMock.getProviderInfos()).thenReturn(metaDataList);

        Map<String, String> parameters = new HashMap<>();
        parameters.put("provider1.OAuth2.clientSecret", "testClientSecret");
        parameters.put("provider2.OAuth2.clientSecret", "test2ClientSecret");
        TestConfig.addConfigValues(parameters);

        beanManagerFake.registerBean(providerSelectionMock, ProviderSelection.class);
        beanManagerFake.endRegistration();
        when(providerSelectionMock.getProvider()).thenReturn("provider2");

        String clientSecret = configuration.getClientSecret();
        assertThat(clientSecret).isEqualTo("test2ClientSecret");
    }

    public static class TestOAuth2Provider implements OAuth2Provider {

        private String name;

        public TestOAuth2Provider() {
            this(null);
        }

        public TestOAuth2Provider(String name) {
            this.name = name;

        }

        @Override
        public String getName() {
            return name;
        }

    }

}