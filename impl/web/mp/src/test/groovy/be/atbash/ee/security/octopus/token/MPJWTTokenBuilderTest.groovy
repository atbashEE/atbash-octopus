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

import be.atbash.ee.security.octopus.config.MPConfiguration
import com.blogspot.toomuchcoding.spock.subjcollabs.Collaborator
import com.blogspot.toomuchcoding.spock.subjcollabs.Subject
import groovy.time.TimeCategory
import spock.lang.Specification

/**
 *
 */

class MPJWTTokenBuilderTest extends Specification {

    @Collaborator
    MPConfiguration mpConfigurationStub = Stub(MPConfiguration)

    @Subject
    MPJWTTokenBuilder tokenBuilder

    def "Build"() {
        given:
        tokenBuilder.init()

        Date now = new Date()
        Date exp = use(TimeCategory) {
            now + 30.minutes
        }

        tokenBuilder.setIssuer("ISS")
        tokenBuilder.setAudience("AUD")
        tokenBuilder.setIssuedAtTime(now)
        tokenBuilder.setExpirationTime(exp)
        tokenBuilder.setSubject("Subject")

        when:
        MPJWTToken token = tokenBuilder.build()

        then:
        token.iss == "ISS"
        token.aud == "AUD"
        token.iat == now.getTime()
        token.exp == now.getTime() + 30 * 60 * 1000
        token.sub == "Subject"
        token.upn == null
    }

    def "Build_setExpirationPeriod"() {
        given:
        tokenBuilder.init()

        Date now = new Date()

        tokenBuilder.setIssuer("ISS")
        tokenBuilder.setAudience("AUD")
        tokenBuilder.setIssuedAtTime(now)
        tokenBuilder.setExpirationPeriod("2m")
        tokenBuilder.setSubject("Subject")

        when:
        MPJWTToken token = tokenBuilder.build()

        then:
        token.iss == "ISS"
        token.aud == "AUD"
        token.iat == now.getTime()
        token.exp > token.iat + 2 * 60 * 1000
        token.exp - 100 < token.iat + 2 * 60 * 1000  // 0.1 sec skew
        token.sub == "Subject"
        token.upn == null
    }

    def "Build_defaults"() {
        given:
        tokenBuilder.init()
        mpConfigurationStub.issuer >> "SSI"
        mpConfigurationStub.audience >> "DUA"
        mpConfigurationStub.expirationTime >> "3s"

        Date now = new Date()
        tokenBuilder.setSubject("tcejbuS")

        when:
        MPJWTToken token = tokenBuilder.build()

        then:
        token.iss == "SSI"
        token.aud == "DUA"
        token.iat - now.getTime() < 100  // Faster then 0.1 sec
        token.exp == token.iat + 3 * 1000
        token.sub == "tcejbuS"
        token.upn == null
    }

    def "Build_missingIss"() {
        given:
        tokenBuilder.init()

        Date now = new Date()
        Date exp = use(TimeCategory) {
            now + 30.minutes
        }

        tokenBuilder.setAudience("AUD")
        tokenBuilder.setIssuedAtTime(now)
        tokenBuilder.setExpirationTime(exp)
        tokenBuilder.setSubject("Subject")

        when:

        tokenBuilder.build()

        then:
        def ex = thrown(MissingClaimMPJWTTokenException)
        ex.message.contains("'iss'")
    }

    def "Build_missingAud"() {
        given:
        tokenBuilder.init()

        Date now = new Date()
        Date exp = use(TimeCategory) {
            now + 30.minutes
        }

        tokenBuilder.setIssuer("ISS")
        tokenBuilder.setIssuedAtTime(now)
        tokenBuilder.setExpirationTime(exp)
        tokenBuilder.setSubject("Subject")

        when:

        tokenBuilder.build()

        then:
        def ex = thrown(MissingClaimMPJWTTokenException)
        ex.message.contains("'aud'")
    }

    def "Build_missingExp"() {
        given:
        tokenBuilder.init()

        tokenBuilder.setIssuer("ISS")
        tokenBuilder.setAudience("AUD")
        tokenBuilder.setSubject("Subject")

        when:

        tokenBuilder.build()

        then:
        def ex = thrown(MissingClaimMPJWTTokenException)
        ex.message.contains("'exp'")
    }

    def "Build_missingSubUpn"() {
        given:
        tokenBuilder.init()

        Date now = new Date()
        Date exp = use(TimeCategory) {
            now + 30.minutes
        }

        tokenBuilder.setIssuer("ISS")
        tokenBuilder.setAudience("AUD")
        tokenBuilder.setIssuedAtTime(now)
        tokenBuilder.setExpirationTime(exp)

        when:

        tokenBuilder.build()

        then:
        def ex = thrown(MissingClaimMPJWTTokenException)
        ex.message.contains("'sub' and 'upn'")
    }

}
