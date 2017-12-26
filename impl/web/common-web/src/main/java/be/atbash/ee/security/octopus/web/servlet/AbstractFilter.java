/*
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
package be.atbash.ee.security.octopus.web.servlet;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.util.Reviewed;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

/**
 * Base abstract Filter simplifying Filter creation by providing empty implementations of {@link #init(FilterConfig) readInfo}
 * and {@link #destroy() destroy} methods.
 * <p>
 * FilterChain execution logic (the
 * {@link #doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)} method
 * is left to subclasses.
 * <p>
 * It is also the base class for all 'Octopus' Based filters which are used within the FilterChain concept.
 */
@Reviewed
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.servlet.AbstractFilter"})
public abstract class AbstractFilter implements Filter {

    /**
     * Default no-op implementation that can be overridden by subclasses for custom readInfo behavior.
     * But be aware that most filters are 'Octopus' Filters and thus CDI based and not really instantiated by the
     * system. And thus readInfo should be achieved by a @PostConstruct method.
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    /**
     * Default no-op implementation that can be overridden by subclasses for custom cleanup behavior.
     * But be aware that most filters are 'Octopus' Filters and thus CDI based and not really instantiated by the
     * system. And thus readInfo should be achieved by a @PreDestroy method.
     */
    @Override
    public void destroy() {
    }

    /**
     * It is highly recommended not to override this method directly, and instead override the
     * {@link #toStringBuilder() toStringBuilder()} method, a better-performing alternative.
     *
     * @return the String representation of this instance.
     */
    @Override
    public String toString() {
        return toStringBuilder().toString();
    }

    /**
     * Same concept as {@link #toString() toString()}, but returns a {@link StringBuilder} instance instead.
     *
     * @return a StringBuilder instance to use for appending String data that will eventually be returned from a
     * {@code toString()} invocation.
     */
    // TODO  Implement this in all subclasses
    protected StringBuilder toStringBuilder() {
        return new StringBuilder(super.toString());
    }
}