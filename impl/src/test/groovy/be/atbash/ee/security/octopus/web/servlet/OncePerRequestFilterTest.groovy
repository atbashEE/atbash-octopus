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
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 */

class OncePerRequestFilterTest extends Specification {

    public static final String EXCEPTION_MESSAGE = "doFilterInternal Exception message"
    OncePerRequestFilter filter

    boolean throwException

    boolean filterMethodCalled
    boolean filterAttributeSet
    boolean filterAttributeRemoved

    String filterName = "Spock"
    String filterAttributeName

    String attributeName


    def setup() {
        filter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
                filterMethodCalled = true
                if (throwException) {
                    throw new ServletException(EXCEPTION_MESSAGE)
                }
            }
        }

        filterMethodCalled = false
        filterAttributeSet = false
        filterAttributeRemoved = false
        attributeName = OncePerRequestFilterTest.name + "\$1.FILTERED"

        filterAttributeName = filterName + ".FILTERED"
    }


    def doFilter() {

        given:
        HttpServletRequest servletRequestStub = Mock(HttpServletRequest)
        throwException = false
        filter.setName(filterName)

        when:
        filter.doFilter(servletRequestStub, null, null)

        then:
        // There is an important order. First we need to setAttribute, call method, remove attribute
        1 * servletRequestStub.getAttribute(filterAttributeName)
        servletRequestStub.setAttribute(*_) >> { arguments ->
            assert arguments[0] == filterAttributeName
            filterAttributeSet = arguments[1]
        }
        filterAttributeSet

        then:
        // There is an important order. First we need to setAttribute, call method, remove attribute
        filterMethodCalled

        then:
        // There is an important order. First we need to setAttribute, call method, remove attribute
        servletRequestStub.removeAttribute(*_) >> { arguments ->
            assert arguments[0] == filterAttributeName
            filterAttributeRemoved = true
        }
        filterAttributeRemoved

        then:
        0 * _
    }

    def doFilter_noName() {

        given:
        HttpServletRequest servletRequestStub = Mock(HttpServletRequest)
        throwException = false

        when:
        filter.doFilter(servletRequestStub, null, null)

        then:
        // There is an important order. First we need to setAttribute, call method, remove attribute
        1 * servletRequestStub.getAttribute(attributeName)
        servletRequestStub.setAttribute(*_) >> { arguments ->
            assert arguments[0] == attributeName
            filterAttributeSet = arguments[1]
        }
        filterAttributeSet

        then:
        // There is an important order. First we need to setAttribute, call method, remove attribute
        filterMethodCalled

        then:
        // There is an important order. First we need to setAttribute, call method, remove attribute
        servletRequestStub.removeAttribute(*_) >> { arguments ->
            assert arguments[0] == attributeName
            filterAttributeRemoved = true
        }
        filterAttributeRemoved

        then:
        0 * _
    }

    def doFilter_Exception() {

        given:
        HttpServletRequest servletRequestStub = Mock(HttpServletRequest)
        throwException = true

        when:
        filter.doFilter(servletRequestStub, null, null)

        then:
        // There is an important order. First we need to setAttribute, call method, remove attribute
        1 * servletRequestStub.getAttribute(attributeName)
        filterAttributeSet
        servletRequestStub.setAttribute(*_) >> { arguments ->
            assert arguments[0] == attributeName
            filterAttributeSet = arguments[1]
        }

        then:
        // There is an important order. First we need to setAttribute, call method, remove attribute
        filterMethodCalled

        then:
        // There is an important order. First we need to setAttribute, call method, remove attribute
        filterAttributeRemoved
        servletRequestStub.removeAttribute(*_) >> { arguments ->
            assert arguments[0] == attributeName
            filterAttributeRemoved = true
        }

        then:
        def e = thrown(ServletException)
        e.message == EXCEPTION_MESSAGE

        then:
        0 * _
    }

    def doFilter_alreadyFiltered() {

        given:
        filter.setName(filterName)

        HttpServletRequest servletRequestMock = Stub(HttpServletRequest)

        FilterChain filterChainMock = Mock(FilterChain)

        when:
        filter.doFilter(servletRequestMock, null, filterChainMock)

        then:
        1 * filterChainMock.doFilter(_, _)
        servletRequestMock.getAttribute(_) >> { arguments ->
            arguments[0] = filterAttributeName
            return Boolean.TRUE
        }
        !filterMethodCalled
        !filterAttributeSet
        !filterAttributeRemoved
        0 * _
    }

    def isEnabled_Default() {

        expect:
        filter.isEnabled()
        filter.isEnabled(null, null) // By default it just passes control to isEnabled() and not using the parameters

    }

    def isEnabled_disabled() {

        given:
        filter.setEnabled(false)

        when:
        boolean enabled = filter.isEnabled()

        then:

        !enabled
        0 * _
    }

    def doFilter_disabled() {

        given:
        HttpServletRequest servletRequestMock = Mock(HttpServletRequest)
        filter.setName(filterName)
        filter.setEnabled(false)

        FilterChain filterChainMock = Mock(FilterChain)

        when:
        filter.doFilter(servletRequestMock, null, filterChainMock)

        then:
        1 * filterChainMock.doFilter(_, _)
        servletRequestMock.getAttribute(_) >> { arguments ->
            arguments[0] = filterAttributeName
            return null
        }
        !filterMethodCalled
        !filterAttributeSet
        !filterAttributeRemoved
        0 * _
    }
}
