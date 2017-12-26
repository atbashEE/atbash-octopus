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
package be.atbash.ee.security.octopus.token

import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder
import spock.lang.Specification

/**
 *
 */

class MPJWTTokenTest extends Specification {

    def "toJSONString_additionalClaims"() {
        given:
        MPJWTToken token = new MPJWTToken()

        token.setExp(new Date().getTime())
        token.setIat(new Date().getTime())

        token.setAdditionalClaims([extra: 'Spock', framework: 'Octopus'])


        when:
        String json = token.toJSONString()

        then:
        json.contains("\"framework\":\"Octopus\"")
        json.contains("\"extra\":\"Spock\"")

    }

    def "Decode"() {
        given:
        JWTDecoder decoder = new JWTDecoder();

        when:
        MPJWTToken token = decoder.decode("{\"framework\":\"Octopus\",\"extra\":\"Spock\",\"exp\":1514288343,\"iat\":1514288343}", MPJWTToken.class)

        then:
        token.getAdditionalClaims() == [extra: 'Spock', framework: 'Octopus']
    }
}
