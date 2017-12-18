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

import be.atbash.ee.security.octopus.jwt.keys.HMACSecret
import be.atbash.ee.security.octopus.jwt.keys.SecretKeyType
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import spock.lang.Specification

/**
 * Only normal usages are tested.
 * TODO : Test abnormal combinations
 */

class JWTParametersSigningTest extends Specification {

    def "GetKeyID_hmac"() {

        given:
        HMACSecret hmac = new HMACSecret("secret", "hmacKeyId", false)

        when:
        JWTParametersSigning parameters = new JWTParametersSigning(null, SecretKeyType.HMAC, null, hmac)

        then:
        parameters.keyID == "hmacKeyId"
    }

    def "GetKeyID_rsa"() {

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
        JWTParametersSigning parameters = new JWTParametersSigning(null, SecretKeyType.RSA, rsa, null)

        then:
        parameters.keyID == "rsaKeyId"
    }

    def "GetKeyID_ec"() {

        given:
        JWK rsa = new JWK(KeyType.EC, null, null, null, "ecKeyId", null, null, null, null, null) {

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
        JWTParametersSigning parameters = new JWTParametersSigning(null, SecretKeyType.EC, rsa, null)

        then:
        parameters.keyID == "ecKeyId"
    }
}
