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

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import org.junit.After;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class OctopusSSOClientConfigurationTest {

    private OctopusSSOClientConfiguration configuration = new OctopusSSOClientConfiguration();

    @After
    public void teardown() {
        TestConfig.resetConfig();
    }

    @Test
    public void getLoginPage() {
        TestConfig.addConfigValue("SSO.octopus.server", "http://sso.server.org/root");

        assertThat(configuration.getLoginPage()).isEqualTo("http://sso.server.org/root/octopus/sso/authenticate");
    }

    @Test
    public void getSSOServer() {
        TestConfig.addConfigValue("SSO.octopus.server", "http://sso.server.org/root");

        assertThat(configuration.getSSOServer()).isEqualTo("http://sso.server.org/root");
    }

    @Test(expected = ConfigurationException.class)
    public void getSSOServer_missing() {

        configuration.getSSOServer();
    }
}