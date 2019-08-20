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
package be.atbash.ee.security.octopus.sso.config;

import be.atbash.ee.security.octopus.sso.client.config.OctopusSSOServerClientConfiguration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class OctopusSSOClientConfigurationTest {

    @Mock
    private OctopusSSOServerClientConfiguration serverClientConfigurationMock;

    @InjectMocks
    private OctopusSSOClientConfiguration configuration;

    @Test
    public void getLoginPage() {
        when(serverClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://sso.server.org/root");

        assertThat(configuration.getLoginPage()).isEqualTo("http://sso.server.org/root/octopus/sso/authenticate");
    }

}