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
package be.atbash.ee.security.octopus.util

import spock.lang.Specification

/**
 *
 */

class StringUtilsTest extends Specification {

    def "CountOccurrences"() {
        expect:
            StringUtils.countOccurrences("abcabc", 'a' as char) == 2

    }

    def "CountOccurrences_notFound"() {
        expect:
            StringUtils.countOccurrences("abcabc", 'd' as char) == 0

    }

    def "CountOccurrences_empty"() {
        expect:
            StringUtils.countOccurrences("", 'd' as char) == 0

    }

    def "CountOccurrences_null"() {
        expect:
            StringUtils.countOccurrences(null, 'd' as char) == 0

    }


}
