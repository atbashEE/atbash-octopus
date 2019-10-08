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
package be.atbash.ee.security.octopus.sso.client.config;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import org.junit.After;
import org.junit.Test;

import java.util.Base64;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

public class OctopusSSOServerClientConfigurationTest {

    private OctopusSSOServerClientConfiguration configuration = new OctopusSSOServerClientConfiguration();

    private Random random = new Random();

    @After
    public void tearDown() {
        TestConfig.resetConfig();
    }

    @Test
    public void getSSOClientSecret() {
        byte[] value = new byte[32];
        random.nextBytes(value);
        TestConfig.addConfigValue("SSO.clientSecret", Base64.getEncoder().withoutPadding().encodeToString(value));

        byte[] secret = configuration.getSSOClientSecret();
        assertThat(secret).isEqualTo(value);
    }

    @Test(expected = ConfigurationException.class)
    public void getSSOClientSecret_tooShort() {
        byte[] value = new byte[31];
        random.nextBytes(value);
        TestConfig.addConfigValue("SSO.clientSecret", Base64.getEncoder().withoutPadding().encodeToString(value));

        configuration.getSSOClientSecret();
    }

    @Test(expected = ConfigurationException.class)
    public void getSSOClientSecret_notDefined() {
        configuration.getSSOClientSecret();
    }

    @Test
    public void getSSOClientSecret_withPrefix() {
        TestConfig.addConfigValue("SSO.application", "test");
        byte[] value1 = new byte[32];
        random.nextBytes(value1);
        TestConfig.addConfigValue("test.SSO.clientSecret",Base64.getEncoder().withoutPadding().encodeToString(value1));

        byte[] value2 = new byte[32];
        random.nextBytes(value2);
        TestConfig.addConfigValue("SSO.clientSecret", Base64.getEncoder().withoutPadding().encodeToString(value2));

        byte[] secret = configuration.getSSOClientSecret();
        assertThat(secret).isEqualTo(value1);
    }

    @Test
    public void getSSOIdTokenSecret() {
        byte[] value = new byte[32];
        random.nextBytes(value);
        TestConfig.addConfigValue("SSO.idTokenSecret", Base64.getEncoder().withoutPadding().encodeToString(value));

        byte[] secret = configuration.getSSOIdTokenSecret();
        assertThat(secret).isEqualTo(value);
    }

    @Test(expected = ConfigurationException.class)
    public void getSSOIdTokenSecret_tooShort() {
        byte[] value = new byte[31];
        random.nextBytes(value);
        TestConfig.addConfigValue("SSO.idTokenSecret", Base64.getEncoder().withoutPadding().encodeToString(value));

        configuration.getSSOIdTokenSecret();

    }

    @Test(expected = ConfigurationException.class)
    public void getSSOIdTokenSecret_notDefined() {
        configuration.getSSOIdTokenSecret();
    }

    @Test
    public void getSSOIdTokenSecret_withPrefix() {

        TestConfig.addConfigValue("SSO.application", "test");
        byte[] value1 = new byte[32];
        random.nextBytes(value1);
        TestConfig.addConfigValue("test.SSO.idTokenSecret", Base64.getEncoder().withoutPadding().encodeToString(value1));

        byte[] value2 = new byte[32];
        random.nextBytes(value2);
        TestConfig.addConfigValue("SSO.idTokenSecret", Base64.getEncoder().withoutPadding().encodeToString(value2));

        byte[] secret = configuration.getSSOIdTokenSecret();
        assertThat(secret).isEqualTo(value1);
    }

    @Test
    public void getSSOServer() {
        TestConfig.addConfigValue("SSO.octopus.server", "http://sso.server.org/root");

        assertThat(configuration.getOctopusSSOServer()).isEqualTo("http://sso.server.org/root");
    }

    @Test(expected = ConfigurationException.class)
    public void getSSOServer_missing() {

        configuration.getOctopusSSOServer();
    }
}