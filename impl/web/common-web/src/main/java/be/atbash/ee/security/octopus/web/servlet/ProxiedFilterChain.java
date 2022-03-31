/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.filter.AdviceFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.*;
import java.io.IOException;
import java.util.List;

/**
 * A proxied filter chain is a {@link FilterChain} instance that proxies an original {@link FilterChain} as well
 * as a {@link List List} of other {@link Filter Filter}s that might need to execute prior to the final wrapped
 * original chain.  It allows a list of filters to execute before continuing the original (proxied)
 * {@code FilterChain} instance.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.servlet.ProxiedFilterChain"})
public class ProxiedFilterChain implements FilterChain {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(ProxiedFilterChain.class);

    private FilterChain orig;
    private List<AdviceFilter> filters;
    private int index;

    public ProxiedFilterChain(FilterChain orig, List<AdviceFilter> filters) {
        if (orig == null) {
            throw new NullPointerException("original FilterChain cannot be null.");
        }
        this.orig = orig;
        this.filters = filters;
        index = 0;
    }

    public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        if (filters == null || filters.size() == index) {
            //we've reached the end of the wrapped chain, so invoke the original one:
            if (log.isTraceEnabled()) {
                log.trace("Invoking original filter chain.");
            }
            orig.doFilter(request, response);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Invoking wrapped filter at index [" + index + "]");
            }
            filters.get(index++).doFilter(request, response, this);
        }
    }
}
