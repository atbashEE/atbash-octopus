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
package be.atbash.ee.security.octopus.jwt.parameter

import be.atbash.ee.security.octopus.jwt.JWTEncoding
import be.atbash.ee.security.octopus.jwt.keys.HMACSecret
import be.atbash.ee.security.octopus.jwt.keys.SecretKeyType
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import spock.lang.Specification

import java.security.SecureRandom

/**
 *
 */

class JWTParametersBuilderTest extends Specification {
    def "WithHeader_default"() {

        when:
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(new HMACSecret("testSecret", "Spock", false))
                .withHeader("UnitTest", "Spock")
                .build()

        then:
        parameters instanceof JWTParametersSigning
        JWTParametersSigning parametersSigning = parameters as JWTParametersSigning
        parametersSigning.encoding == JWTEncoding.JWS
        parametersSigning.headerValues == [UnitTest: 'Spock']
    }

    def "WithHeader_multiple"() {

        when:
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(new HMACSecret("testSecret", "Spock", false))
                .withHeader("UnitTest", "Spock")
                .withHeader("key", "value")
                .build()

        then:
        parameters instanceof JWTParametersSigning
        JWTParametersSigning parametersSigning = parameters as JWTParametersSigning
        parametersSigning.encoding == JWTEncoding.JWS
        parametersSigning.headerValues == [UnitTest: 'Spock', key: 'value']
    }

    def "WithHeader_none"() {

        when:
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(new HMACSecret("testSecret", "Spock", false))
                .build()

        then:
        parameters instanceof JWTParametersSigning
        JWTParametersSigning parametersSigning = parameters as JWTParametersSigning
        parametersSigning.encoding == JWTEncoding.JWS
        parametersSigning.headerValues == null
    }

    def "WithHeader_encodingNone"() {

        when:
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE)
                .withSecretKeyForSigning(new HMACSecret("testSecret", "Spock", false))
                .withHeader("UnitTest", "Spock")
                .build()

        then:
        parameters instanceof JWTParametersNone
        // TODO How can we check that there is a message in the log.
    }

    def "validate_requiredKeys"() {

        when:
        JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .build()

        then:
        thrown ConfigurationException
    }

    def "build_propagatesKeyType"() {

        when:
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(new HMACSecret("testSecret", "Spock", false))
                .build()

        then:
        parameters instanceof JWTParametersSigning
        JWTParametersSigning parametersSigning = parameters as JWTParametersSigning
        parametersSigning.encoding == JWTEncoding.JWS
        parametersSigning.secretKeyType == SecretKeyType.HMAC
    }

    def "JWKKeyType_RSA"() {

        given:
        JWK rsa = new JWK(KeyType.RSA, null, null, null, "rsaKeyId", null, null, null, null, null) {

            @Override
            LinkedHashMap<String, ?> getRequiredParams() {
                return null
            }

            @Override
            boolean isPrivate() {
                return false
            }

            @Override
            JWK toPublicJWK() {
                return null
            }

            @Override
            int size() {
                return 0
            }
        }

        when:
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(rsa)
                .build()
        then:
        parameters instanceof JWTParametersSigning
        JWTParametersSigning parametersSigning = parameters as JWTParametersSigning
        parametersSigning.encoding == JWTEncoding.JWS
        parametersSigning.secretKeyType == SecretKeyType.RSA
    }

    def "JWKKeyType_hmac"() {

        given:
        byte[] secret = new byte[16]
        new SecureRandom().nextBytes(secret)

        HMACSecret hmac = new HMACSecret(secret, "hmacKeyId")

        when:
        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(hmac)
                .build()
        then:
        parameters instanceof JWTParametersSigning
        JWTParametersSigning parametersSigning = parameters as JWTParametersSigning
        parametersSigning.encoding == JWTEncoding.JWS
        parametersSigning.secretKeyType == SecretKeyType.HMAC
    }
}
