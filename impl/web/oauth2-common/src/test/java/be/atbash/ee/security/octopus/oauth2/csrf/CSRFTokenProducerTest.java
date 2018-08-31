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
package be.atbash.ee.security.octopus.oauth2.csrf;

import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class CSRFTokenProducerTest {

    @Test
    public void nextToken_length() {
        CSRFTokenProducer tokenProducer = new CSRFTokenProducer();
        tokenProducer.init();
        String token = tokenProducer.nextToken();
        assertThat(token).hasSize(26);
    }

    @Test
    public void nextToken_unique() {
        CSRFTokenProducer tokenProducer = new CSRFTokenProducer();
        tokenProducer.init();
        Set<String> tokens = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            tokens.add(tokenProducer.nextToken());
        }
        assertThat(tokens).hasSize(50);  // No doubles added to Set so good indication it is unique
    }
}