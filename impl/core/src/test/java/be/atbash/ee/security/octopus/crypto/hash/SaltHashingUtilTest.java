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
package be.atbash.ee.security.octopus.crypto.hash;

import be.atbash.config.test.TestConfig;
import be.atbash.util.TestReflectionUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class SaltHashingUtilTest {

    @Before
    public void setup() {
        TestConfig.registerDefaultConverters();
    }

    @After
    public void teardown() throws NoSuchFieldException {
        TestConfig.resetConfig();
        // Reset SaltHashingUtil so that initialization happens again.
        TestReflectionUtils.setFieldValue(SaltHashingUtil.class, "INSTANCE", null);
    }

    @Test
    public void nextSalt() {
        TestConfig.addConfigValue("saltLength", "16");
        byte[] bytes = SaltHashingUtil.getInstance().nextSalt();
        assertThat(bytes).hasSize(16);
    }

    @Test
    public void nextSalt_DifferentValues() {
        TestConfig.addConfigValue("saltLength", "16");
        byte[] bytes1 = SaltHashingUtil.getInstance().nextSalt();
        byte[] bytes2 = SaltHashingUtil.getInstance().nextSalt();
        assertThat(bytes1).isNotEqualTo(bytes2);
    }

    @Test
    public void hash_inHex() {
        TestConfig.addConfigValue("hashAlgorithmName", "SHA-256");
        String hashValue = SaltHashingUtil.getInstance().hash("Test".toCharArray(), "Atbash".getBytes());
        assertThat(hashValue).isEqualTo("ACEB16B8AABE225073CF471696C45627B6B0C0E2563C658857038ECE54BB34ED");
    }

    @Test
    public void hash_inBase64() {
        TestConfig.addConfigValue("hashAlgorithmName", "SHA-256");
        TestConfig.addConfigValue("hashEncoding", "BASE64");
        String hashValue = SaltHashingUtil.getInstance().hash("Test".toCharArray(), "Atbash".getBytes());
        assertThat(hashValue).isEqualTo("rOsWuKq-IlBzz0cWlsRWJ7awwOJWPGWIVwOOzlS7NO0");
    }
}