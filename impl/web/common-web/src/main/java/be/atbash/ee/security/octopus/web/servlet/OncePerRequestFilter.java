/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter base class that guarantees to be just executed once per request,
 * on any servlet container. It provides a {@link #doFilterInternal}
 * method with HttpServletRequest and HttpServletResponse arguments.
 * <p/>
 * The {@link #getAlreadyFilteredAttributeName} method determines how
 * to identify that a request is already filtered. The default implementation
 * is based on the configured name of the concrete filter instance.
 * <h3>Controlling filter execution</h3>
 * The {@link #isEnabled(ServletRequest, ServletResponse)} method and
 * {@link #isEnabled()} property to allow explicit control over whether the filter executes (or allows passthrough)
 * for any given request.
 * <p/>
 * <b>NOTE</b> This class was initially borrowed from the Spring framework but has continued modifications.
 */
@Reviewed
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.servlet.OncePerRequestFilter"})
public abstract class OncePerRequestFilter extends NameableFilter {

    /**
     * Private internal log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(OncePerRequestFilter.class);

    /**
     * Suffix that gets appended to the filter name for the "already filtered" request attribute.
     *
     * @see #getAlreadyFilteredAttributeName
     */
    public static final String ALREADY_FILTERED_SUFFIX = ".FILTERED";

    /**
     * Determines generally if this filter should execute or let requests fall through to the next chain element.
     *
     * @see #isEnabled()
     */
    private boolean enabled = true; //most filters wish to execute when configured, so default to true

    /**
     * Returns {@code true} if this filter should <em>generally</em><b>*</b> execute for any request,
     * {@code false} if it should let the request/response pass through immediately to the next
     * element in the {@link FilterChain}.  The default value is {@code true}, as most filters would inherently need
     * to execute when configured.
     * <p/>
     * <b>*</b> This configuration property is for general configuration for any request that comes through
     * the filter.  The
     * {@link #isEnabled(ServletRequest, ServletResponse) isEnabled(request,response)}
     * method actually determines whether or not if the filter is enabled based on the current request.
     *
     * @return {@code true} if this filter should <em>generally</em> execute, {@code false} if it should let the
     * request/response pass through immediately to the next element in the {@link FilterChain}.
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether or not this filter <em>generally</em> executes for any request.  See the
     * {@link #isEnabled() isEnabled()} JavaDoc as to what <em>general</em> execution means.
     *
     * @param enabled whether or not this filter <em>generally</em> executes.
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * This {@code doFilter} implementation stores a request attribute for
     * "already filtered", proceeding without filtering again if the
     * attribute is already there.
     *
     * @see #getAlreadyFilteredAttributeName
     * @see #doFilterInternal
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();
        if (request.getAttribute(alreadyFilteredAttributeName) != null) {
            log.trace("Filter '{}' already executed.  Proceeding without invoking this filter.", getName());
            filterChain.doFilter(request, response);
        } else {
            if (!isEnabled(request, response)) {
                log.debug("Filter '{}' is not enabled for the current request.  Proceeding without invoking this filter.",
                        getName());
                filterChain.doFilter(request, response);
            } else {
                // Do invoke this filter...
                log.trace("Filter '{}' not yet executed.  Executing now.", getName());
                request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);

                try {
                    // TODO Maybe do some checks before cast?
                    doFilterInternal((HttpServletRequest) request, (HttpServletResponse) response, filterChain);
                } finally {
                    // Once the request has finished, we're done and we don't
                    // need to mark as 'already filtered' any more.
                    request.removeAttribute(alreadyFilteredAttributeName);
                }
            }
        }
    }

    /**
     * This method is used within the {@link #doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)} doFilterInternal}
     * method to determine if the filter need to be enabled or not.
     * <p>
     * By default is returns the value which is set by the {@link #setEnabled(boolean) setEnabled } method or the default value {@code true}.
     *
     * @param request
     * @param response
     * @return
     * @throws ServletException
     * @throws IOException
     */
    protected boolean isEnabled(ServletRequest request, ServletResponse response) throws ServletException, IOException {
        return isEnabled();
    }

    /**
     * Return name of the request attribute that identifies that a request has already been filtered.
     * <p/>
     * The default implementation takes the configured {@link #getName() name} and appends &quot;{@code .FILTERED}&quot;.
     * If the filter is not fully initialized, it falls back to the implementation's class name.
     * <p>
     * Specific filters can define their own attribute name for identification of this filter is already executed.
     *
     * @return the name of the request attribute that identifies that a request has already been filtered.
     * @see #getName
     * @see #ALREADY_FILTERED_SUFFIX
     */
    protected String getAlreadyFilteredAttributeName() {
        String name = getName();
        if (name == null) {
            name = getClass().getName();
        }
        return name + ALREADY_FILTERED_SUFFIX;
    }

    /**
     * Same contract as for
     * {@link #doFilter(ServletRequest, ServletResponse, FilterChain)},
     * but guaranteed to be invoked only once per request.
     *
     * @param request  incoming {@code ServletRequest}
     * @param response outgoing {@code ServletResponse}
     * @param chain    the {@code FilterChain} to execute
     * @throws ServletException if there is a problem processing the request
     * @throws IOException      if there is an I/O problem processing the request
     */
    protected abstract void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException;
}
