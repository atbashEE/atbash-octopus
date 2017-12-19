/**
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.jwt.encoder

import be.atbash.ee.security.octopus.config.ConfigurationException
import com.nimbusds.jose.JWSAlgorithm
import spock.lang.Specification

import java.security.SecureRandom

/**
 *
 */

class HMACAlgorithmFactoryTest extends Specification {
    def "DetermineOptimalAlgorithm_short"() {
        given:
        byte[] secret = defineSecret(256 / 8 + 1 as int)
        HMACAlgorithmFactory factory = new HMACAlgorithmFactory()

        when:
        JWSAlgorithm algorithm = factory.determineOptimalAlgorithm(secret)

        then:
        algorithm == JWSAlgorithm.HS256
    }

    def "DetermineOptimalAlgorithm_medium"() {
        given:
        byte[] secret = defineSecret(384 / 8 + 1 as int)
        HMACAlgorithmFactory factory = new HMACAlgorithmFactory()

        when:
        JWSAlgorithm algorithm = factory.determineOptimalAlgorithm(secret)

        then:
        algorithm == JWSAlgorithm.HS384
    }

    def "DetermineOptimalAlgorithm_long"() {
        given:
        byte[] secret = defineSecret(512 / 8 + 1 as int)
        HMACAlgorithmFactory factory = new HMACAlgorithmFactory()

        when:
        JWSAlgorithm algorithm = factory.determineOptimalAlgorithm(secret)

        then:
        algorithm == JWSAlgorithm.HS512
    }

    def "tooShort"() {
        //given:  When not commented -> VerifyError: Stack size too large Groovy madness
        byte[] secret = defineSecret(184 / 8 + 1 as int)
        HMACAlgorithmFactory factory = new HMACAlgorithmFactory()

        when:
        factory.determineOptimalAlgorithm(secret)

        then:
        thrown ConfigurationException

    }

    private byte[] defineSecret(int byteLength) {
        byte[] bytes = new byte[byteLength]
        SecureRandom secureRandom = new SecureRandom()
        secureRandom.nextBytes(bytes)

        return bytes
    }
}
