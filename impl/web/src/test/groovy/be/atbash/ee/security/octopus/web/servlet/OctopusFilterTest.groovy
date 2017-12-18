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

import be.atbash.ee.security.octopus.filter.FilterChainResolver
import be.atbash.ee.security.octopus.mgt.WebSecurityManager
import be.atbash.ee.security.octopus.subject.WebSubject
import be.atbash.ee.security.octopus.subject.support.WebSubjectContext
import be.atbash.ee.security.octopus.web.url.SecuredURLReader
import com.blogspot.toomuchcoding.spock.subjcollabs.Collaborator
import com.blogspot.toomuchcoding.spock.subjcollabs.Subject
import spock.lang.Specification

import javax.servlet.FilterChain
import javax.servlet.FilterConfig
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.util.concurrent.ExecutionException

/**
 *
 */
class OctopusFilterTest extends Specification {

    @Collaborator
    WebSecurityManager securityManagerStub = Stub(WebSecurityManager)

    @Collaborator
    FilterChainResolver filterChainResolverStub = Stub(FilterChainResolver)

    @Collaborator
    SecuredURLReader securedURLReaderMock = Mock(SecuredURLReader);

    @Subject
    OctopusFilter filter

    def "init"() {
        // Check if securedURLReaderMock.loadData is called when OctopusFilter is initialized
        given:
        FilterConfig filterConfigMock = Mock(FilterConfig)

        when:
        filter.init(filterConfigMock)

        then:
        1 * securedURLReaderMock.loadData(_)
        1 * filterConfigMock.getServletContext()
        0 * _
    }

    def "executeChain"() {
        // See that resolved chain got executed.
        given:
        FilterChain filterChainMock = Mock(FilterChain) // As it is a interface
        FilterChain filterChainResultMock = Mock(FilterChain) // As it is a interface

        filterChainResolverStub.getChain(_, _, _) >> filterChainResultMock

        when:
        filter.executeChain(null, null, filterChainMock)

        then:
        1 * filterChainResultMock.doFilter(_, _)
        0 * _
    }

    def "executeChain return original"() {
        // See that original chain gots executed when no resolved one is found.
        given:
        FilterChain filterChainMock = Mock(FilterChain) // As it is a interface

        filterChainResolverStub.getChain(_, _, _) >> null

        when:
        filter.executeChain(null, null, filterChainMock)

        then:
        1 * filterChainMock.doFilter(_, _)
        0 * _
    }

    def "doFilterInternal"() {
        // Check if doFilterInternal creates the subject and calls the chain.
        given:
        HttpServletRequest servletRequestMock = Mock(HttpServletRequest)
        HttpServletResponse servletResponseMock = Mock(HttpServletResponse)
        FilterChain filterChainMock = Mock(FilterChain) // As it is a interface

        filterChainResolverStub.getChain(_, _, _) >> null
        // We don't specify the return securityManagerStub.createSubject() here because we want to validate the parameter.
        // It is defined in the then: section (which seems a little bit odd

        when:
        filter.doFilterInternal(servletRequestMock, servletResponseMock, filterChainMock)

        then:
        1 * filterChainMock.doFilter(servletRequestMock, servletResponseMock)
        securityManagerStub.createSubject(*_) >> { arguments ->
            def parameter = arguments[0]
            assert parameter.size() == 3
            def keys = parameter.keySet() as Set
            assert [WebSubjectContext.SERVLET_REQUEST, WebSubjectContext.SERVLET_RESPONSE, WebSubjectContext.SECURITY_MANAGER] as Set == keys
            def values = parameter.values() as Set
            assert [servletRequestMock, servletResponseMock, securityManagerStub] as Set == values


            return new WebSubject(securityManagerStub)
        }
        0 * _
    }

    def "doFilterInternal_ExecutionException"() {
        // Check that an executionException is wrapped within a ServletException
        given:
        HttpServletRequest servletRequestMock = Mock(HttpServletRequest)
        HttpServletResponse servletResponseMock = Mock(HttpServletResponse)
        FilterChain filterChainMock = Mock(FilterChain) // As it is a interface

        filterChainResolverStub.getChain(_, _, _) >> null
        securityManagerStub.createSubject(_) >> { it ->
            throw new ExecutionException("Message", new NullPointerException())
        }

        when:
        filter.doFilterInternal(servletRequestMock, servletResponseMock, filterChainMock)

        then:
        def e = thrown(ServletException)
        assert e.message == "Filtered request failed."
        assert e.rootCause instanceof NullPointerException
        0 * _
    }

    def "doFilterInternal_IOException"() {
        // Check that an IOException is passed unaltered.
        given:
        HttpServletRequest servletRequestMock = Mock(HttpServletRequest)
        HttpServletResponse servletResponseMock = Mock(HttpServletResponse)
        FilterChain filterChainMock = Mock(FilterChain) // As it is a interface

        filterChainResolverStub.getChain(_, _, _) >> null
        securityManagerStub.createSubject(_) >> { it ->
            throw new IOException("Message")
        }

        when:
        filter.doFilterInternal(servletRequestMock, servletResponseMock, filterChainMock)

        then:
        def e = thrown(IOException)
        assert e.message == "Message"
        0 * _
    }

    def "doFilterInternal_ServletException"() {
        // Check that an ServletException is passed unaltered.
        given:
        HttpServletRequest servletRequestMock = Mock(HttpServletRequest)
        HttpServletResponse servletResponseMock = Mock(HttpServletResponse)
        FilterChain filterChainMock = Mock(FilterChain) // As it is a interface

        filterChainResolverStub.getChain(_, _, _) >> null
        securityManagerStub.createSubject(_) >> { it ->
            throw new ServletException("Servlet")
        }

        when:
        filter.doFilterInternal(servletRequestMock, servletResponseMock, filterChainMock)

        then:
        def e = thrown(ServletException)
        assert e.message == "Servlet"
        0 * _
    }
}
