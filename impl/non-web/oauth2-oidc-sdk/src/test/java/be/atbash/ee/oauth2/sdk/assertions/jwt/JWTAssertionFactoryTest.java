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
package be.atbash.ee.oauth2.sdk.assertions.jwt;


import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the JWT assertion factory.
 */
public class JWTAssertionFactoryTest {

    @Test
    public void testSupportedJWA() {

        assertThat(JWTAssertionFactory.supportedJWAs().containsAll(JWSAlgorithm.Family.HMAC_SHA)).isTrue();
        assertThat(JWTAssertionFactory.supportedJWAs().containsAll(JWSAlgorithm.Family.RSA)).isTrue();
        assertThat(JWTAssertionFactory.supportedJWAs().containsAll(JWSAlgorithm.Family.EC)).isTrue();

        int algNum = JWSAlgorithm.Family.HMAC_SHA.size()
                + JWSAlgorithm.Family.RSA.size()
                + JWSAlgorithm.Family.EC.size();

        assertThat(JWTAssertionFactory.supportedJWAs()).hasSize(algNum);
    }
}
