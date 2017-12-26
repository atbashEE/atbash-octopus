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
package be.atbash.ee.security.octopus.util.duration

import be.atbash.config.exception.ConfigurationException
import spock.lang.Specification

/**
 *
 */

class PeriodUtilTest extends Specification {

    def "DefineSecondsInPeriod_sec"() {

        expect:
        PeriodUtil.defineSecondsInPeriod("3s") == 3
    }

    def "DefineSecondsInPeriod_min"() {

        expect:
        PeriodUtil.defineSecondsInPeriod("7m") == 7 * 60
    }

    def "DefineSecondsInPeriod_hour"() {

        expect:
        PeriodUtil.defineSecondsInPeriod("1h") == 3600
    }

    def "DefineSecondsInPeriod_empty"() {

        when:
        PeriodUtil.defineSecondsInPeriod("")

        then:
        thrown ConfigurationException
    }

    def "DefineSecondsInPeriod_null"() {

        when:
        PeriodUtil.defineSecondsInPeriod(null)

        then:
        thrown ConfigurationException
    }

    def "DefineSecondsInPeriod_mixed"() {

        when:
        PeriodUtil.defineSecondsInPeriod("3m10s")

        then:
        thrown ConfigurationException
    }
}
