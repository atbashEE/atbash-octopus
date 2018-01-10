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

import be.atbash.ee.security.octopus.jwt.encoder.testclasses.Payload
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersNone
import spock.lang.Specification

/**
 *
 */

class JWTEncoderTest extends Specification {

    def "EncodeObject_json"() {

        given:

        Payload payload = new Payload()
        payload.value = "Spock"
        payload.number = 42
        payload.myList.add("permission1")
        payload.myList.add("permission2")

        JWTParameters parameters = new JWTParametersNone()

        when:

        JWTEncoder encoder = new JWTEncoder()
        String json = encoder.encode(payload, parameters)

        then:

        assert json == "{\"number\":42,\"myList\":[\"permission1\",\"permission2\"],\"value\":\"Spock\"}"
    }
}