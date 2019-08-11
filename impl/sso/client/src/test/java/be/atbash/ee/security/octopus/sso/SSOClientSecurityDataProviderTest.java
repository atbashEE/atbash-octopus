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
package be.atbash.ee.security.octopus.sso;

import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.StringPermissionLookup;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.sso.client.ClientCustomization;
import be.atbash.ee.security.octopus.sso.client.config.OctopusSSOServerClientConfiguration;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.TestReflectionUtils;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import net.jadler.Jadler;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.ws.rs.client.Client;
import javax.ws.rs.core.Configuration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SSOClientSecurityDataProviderTest {

    @Mock
    private OctopusCoreConfiguration coreConfigurationMock;

    @Mock
    private OctopusSSOServerClientConfiguration clientServerConfigurationMock;

    private BeanManagerFake beanManagerFake = new BeanManagerFake();

    @InjectMocks
    private SSOClientSecurityDataProvider provider;

    @Before
    public void setup() {
        Jadler.initJadler();
        beanManagerFake.registerBean(new JacksonClientCustomization(), ClientCustomization.class);
    }

    @After
    public void teardown() {
        Jadler.closeJadler();
        beanManagerFake.deregistration();
    }

    @Test
    public void createLookup_happyCase() throws NoSuchFieldException {
        beanManagerFake.endRegistration();

        provider.init();

        when(clientServerConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost:" + Jadler.port());
        when(clientServerConfigurationMock.getSSOEndpointRoot()).thenReturn("root");
        when(clientServerConfigurationMock.getSSOApplication()).thenReturn("junit");

        Jadler.onRequest().havingPathEqualTo("/root/octopus/sso/permissions/junit")
                .respond()
                .withStatus(200)
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody("{\"DEMO_WRITE\":\"demo:write:*\",\"SECURITY_ADMIN\":\"security:admin:*\"}");

        StringPermissionLookup lookup = provider.createLookup();
        assertThat(lookup).isNotNull();
        Map<String, NamedDomainPermission> map = TestReflectionUtils.getValueOf(lookup, "map");
        assertThat(map).hasSize(2);
        assertThat(map).containsKeys("DEMO_WRITE", "SECURITY_ADMIN");

    }

    @Test
    public void createLookup_noSSOApplication() throws NoSuchFieldException {
        beanManagerFake.endRegistration();
        provider.init();

        StringPermissionLookup lookup = provider.createLookup();
        assertThat(lookup).isNotNull();
        Map<String, NamedDomainPermission> map = TestReflectionUtils.getValueOf(lookup, "map");
        assertThat(map).isEmpty();
    }

    private static class JacksonClientCustomization implements ClientCustomization {
        // Required to register the JSON functionality when using Java SE.

        @Override
        public void customize(Client client, Class<?> clientUsageClass) {
            client.register(JacksonFeature.class);
        }

        @Override
        public Configuration getConfiguration(Class<?> clientUsageClass) {
            return null;
        }
    }
}