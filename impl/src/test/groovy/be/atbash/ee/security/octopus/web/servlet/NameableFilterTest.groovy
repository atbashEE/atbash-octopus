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
package be.atbash.ee.security.octopus.web.servlet

import spock.lang.Specification

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse

/**
 *
 */

class NameableFilterTest extends Specification {

    NameableFilter filter

    def setup() {
        filter = new NameableFilter() {
            @Override
            void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

            }
        }
    }

    def "setName_noName"() {
        // We do not specify any name
        expect:
        filter.getName() == null
        filter.getNames() == [] as Set
    }

    def "setName_single"() {
        // We only specify a single name, no aliases
        when:
        filter.setName("Filter1")

        then:
        filter.getName() == "Filter1"
        filter.getNames() == ["Filter1"] as Set
    }

    def "setName_multiple"() {
        // The second name we specify is an alias.
        when:
        filter.setName("Filter2")
        filter.setName("Filter1")

        then:
        filter.getName() == "Filter2"
        filter.getNames() == ["Filter1", "Filter2"] as Set
    }

    def "toString_noName"() {
        // We do not specify any name
        expect:
        filter.toString() == NameableFilterTest.getName()+"\$1"
    }

    def "toString_single"() {
        // We only specify a single name, no aliases
        when:
        filter.setName("Filter1")

        then:
        filter.toString() == "Filter1"
    }

    def "toString_multiple"() {
        // The second name we specify is an alias.
        when:
        filter.setName("Filter2")
        filter.setName("Filter1")

        then:
        filter.toString() == "Filter2, Filter1" || "Filter1, Filter2"
    }
}
