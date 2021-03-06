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
package be.atbash.ee.security.octopus.cas.config;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class OctopusCasConfigurationTest {

    private OctopusCasConfiguration configuration;

    @BeforeEach
    public void setup() {
        configuration = OctopusCasConfiguration.getInstance();
    }

    @AfterEach
    public void teardown() {
        TestConfig.resetConfig();
    }

    @Test
    public void getSSOServer_missing() {
        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getSSOServer());
    }

    @Test
    public void getSSOServer() {
        TestConfig.addConfigValue("CAS.SSO.server", "http://localhost");
        configuration.getSSOServer();
    }

    @Test
    public void getCASProtocol_default() {
        CASProtocol result = configuration.getCASProtocol();
        assertThat(result).isEqualTo(CASProtocol.CAS);
    }

    @Test
    public void getCASProtocol_SAML() {
        TestConfig.addConfigValue("CAS.protocol", "saml");

        CASProtocol result = configuration.getCASProtocol();
        assertThat(result).isEqualTo(CASProtocol.SAML);
    }

    @Test
    public void getCASProtocol_cas() {
        TestConfig.addConfigValue("CAS.protocol", "cas");

        CASProtocol result = configuration.getCASProtocol();
        assertThat(result).isEqualTo(CASProtocol.CAS);
    }

    @Test
    public void getCASProtocol_Unknown() {
        TestConfig.addConfigValue("CAS.protocol", "JUnit");

        Assertions.assertThrows(ConfigurationException.class, () -> configuration.getCASProtocol());
    }

}