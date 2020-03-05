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
package be.atbash.ee.security.octopus.token;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class LocalSecretFactoryTest {

    @Test
    public void generateSecret_noTime() {

        byte[] secret1 = LocalSecretFactory.generateSecret("JUnit");
        byte[] secret2 = LocalSecretFactory.generateSecret("JUnit");

        assertThat(secret1).isEqualTo(secret2);
    }

    @Test
    public void generateSecret_passPhraseUsed() {

        byte[] secret1 = LocalSecretFactory.generateSecret("JUnit");
        byte[] secret2 = LocalSecretFactory.generateSecret("jUnit");

        assertThat(secret1).isNotEqualTo(secret2);
    }

}
