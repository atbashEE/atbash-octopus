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
package be.atbash.ee.security.octopus.jwt.keys

import spock.lang.Specification

import java.nio.charset.Charset

/**
 * FIXME contains only the happy cases for the moment.
 */
class HMACSecretTest extends Specification {

    def "GetSecret_asByte"() {

        given:
            Random r = new Random()
            byte[] secret = new byte[16]
            r.nextBytes(secret)

        when:
            HMACSecret hmacSecret = new HMACSecret(secret, "Spock")

        then:
            hmacSecret.secret == secret
    }

    def "GetSecret_asString"() {


        when:
            HMACSecret hmacSecret = new HMACSecret("base64", "Spock", false)

        then:
            hmacSecret.secret == "base64".getBytes(Charset.forName("UTF-8"))
    }

    def "GetSecret_asBase64String"() {

        when:
            HMACSecret hmacSecret = new HMACSecret("base64", "Spock", true)

        then:
            hmacSecret.secret == [109, -85, 30, -21] as byte[]
    }
}
