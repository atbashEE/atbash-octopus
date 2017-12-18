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
package be.atbash.ee.security.octopus.jwt

import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder
import be.atbash.ee.security.octopus.jwt.encoder.testclasses.Payload
import be.atbash.ee.security.octopus.jwt.keys.HMACSecret
import be.atbash.ee.security.octopus.jwt.keys.KeySelector
import be.atbash.ee.security.octopus.jwt.keys.SingleKeySelector
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder
import spock.lang.Specification

import java.security.SecureRandom

/**
 *
 */

class JWTTest extends Specification {

    Payload payload

    def setup() {
        payload = new Payload()
        payload.value = "Spock"
        payload.number = 42
        payload.myList.add("permission1")
        payload.myList.add("permission2")

    }

    def "encodingNone"() {

        when:

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build()
        String encoded = new JWTEncoder().encode(payload, parameters)

        Payload data = new JWTDecoder().decode(encoded, Payload)

        then:
        payload == data
    }

    def "encodingJWT_HMAC"() {

        given:
        byte[] secret = new byte[32]
        new SecureRandom().nextBytes(secret)

        HMACSecret hmac = new HMACSecret(secret, "hmacID")

        when:

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(hmac)
                .build()
        String encoded = new JWTEncoder().encode(payload, parameters)

        KeySelector keySelector = new SingleKeySelector(hmac)
        Payload data = new JWTDecoder().decode(encoded, Payload, keySelector, null).data

        then:
        payload == data
    }
}