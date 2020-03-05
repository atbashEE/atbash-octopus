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
package be.atbash.ee.oauth2.sdk.pkce;


import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Code verifier test.
 */
public class CodeVerifierTest {

    @Test
    public void testLengthLimitConstants() {

        assertThat(CodeVerifier.MIN_LENGTH).isEqualTo(43);
        assertThat(CodeVerifier.MAX_LENGTH).isEqualTo(128);
    }

    @Test
    public void testDefaultConstructor() {

        CodeVerifier verifier = new CodeVerifier();
        assertThat(verifier.getValue().length()).isEqualTo(43);
    }

    @Test
    public void testEquality() {

        CodeVerifier verifier = new CodeVerifier();

        assertThat(verifier.equals(new CodeVerifier(new Base64URLValue(verifier.getValue())))).isTrue();
    }

    @Test
    public void testInequality() {

        assertThat(new CodeVerifier().equals(new CodeVerifier())).isFalse();
        assertThat(new CodeVerifier().equals(null)).isFalse();
    }
}
