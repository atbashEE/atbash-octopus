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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class KeyFactoryNameFactoryTest extends AbstractKeyNameTest {

    private KeyFactoryNameFactory factory = KeyFactoryNameFactory.getInstance();

    @Test
    public void getKeyFactoryName() {

        String expected = defineExpectedName();

        assertThat(factory.getKeyFactoryName("PBKDF2")).isEqualTo(expected);
    }

    @Test
    public void getKeyFactoryName_lowercase() {
        String expected = defineExpectedName();

        assertThat(factory.getKeyFactoryName("pbkdf2")).isEqualTo(expected);
    }

    @Test
    public void getKeyFactoryName_other() {
        assertThat(factory.getKeyFactoryName("sha-256")).isEqualTo("sha-256");
    }

}