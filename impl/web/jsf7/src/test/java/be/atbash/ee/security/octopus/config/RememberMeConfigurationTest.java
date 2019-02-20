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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.crypto.AESCipherService;
import be.atbash.util.base64.Base64Codec;
import org.junit.After;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


public class RememberMeConfigurationTest {

    private RememberMeConfiguration configuration = new RememberMeConfiguration();

    @After
    public void cleanup() {
        TestConfig.resetConfig();
    }

    @Test
    public void getCipherKey_defined() {
        byte[] value = new AESCipherService().generateNewKey().getEncoded();
        TestConfig.addConfigValue("octopus.rememberme.cipherkey", Base64Codec.encodeToString(value, false));

        byte[] cipherKey = configuration.getCipherKey();
        assertThat(cipherKey).isEqualTo(value);
    }

    @Test
    public void getCipherKey_someDefault() {

        byte[] cipherKey = configuration.getCipherKey();
        assertThat(cipherKey).isNotNull();
    }

    @Test(expected = ConfigurationException.class)
    public void getCipherKey_invalid() {

        TestConfig.addConfigValue("octopus.rememberme.cipherkey", "XYZ");

        configuration.getCipherKey();
    }

}