/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.filter;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.filter.mgt.FilterChainManager;
import be.atbash.ee.security.octopus.util.PatternMatcher;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.util.Reviewed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * A {@code FilterChainResolver} can resolve an appropriate {@link FilterChain} which can be executed for any given
 * request or URI/URL. The name of the matched pattern is set as attribute on the request with name {@code OCTOPUS_CHAIN_NAME}.
 * <p/>
 * This mechanism allows for a much more flexible FilterChain resolution than normal {@code web.xml} servlet filter
 * definitions:  it allows arbitrary filter chains to be defined per URL in a much more concise and easy to read manner,
 * and even allows filter chains to be dynamically resolved or constructed at runtime if the underlying implementation
 * supports it.
 */
@ApplicationScoped
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.filter.mgt.FilterChainResolver", "org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver"})
@Reviewed
public class FilterChainResolver {
    public static final String OCTOPUS_CHAIN_NAME = "octopus.chainName";

    private static final Logger log = LoggerFactory.getLogger(FilterChainResolver.class);

    @Inject
    private FilterChainManager filterChainManager;

    @Inject
    private PatternMatcher pathMatcher;

    /**
     * Resolves the {@link FilterChain} for the request. If a match is found, the chain is wrapped within a ProxiedFilterChain together with the original
     * Filterchain (from the servlet environment)
     *
     * @param request       the incoming ServletRequest
     * @param response      the outgoing ServletResponse
     * @param originalChain the original {@code FilterChain} intercepted by the ShiroFilter implementation.
     * @return the filter chain that should be executed for the given request, or {@code null} if the
     * original chain should be used.
     */
    public FilterChain getChain(ServletRequest request, ServletResponse response, FilterChain originalChain) {
        if (!filterChainManager.hasChains()) {
            return null;
        }

        String requestURI = getPathWithinApplication(request);

        //the 'chain names' in this implementation are actually path patterns defined by the user.  We just use them
        //as the chain name for the FilterChainManager's requirements
        for (String pathPattern : filterChainManager.getChainNames()) {

            // If the path does match, then pass on to the subclass implementation for specific checks:
            if (pathMatches(pathPattern, requestURI)) {
                if (log.isTraceEnabled()) {
                    log.trace(String.format("Matched path pattern [%s] for requestURI [%s].  " +
                            "Utilizing corresponding filter chain...", pathPattern, requestURI));
                }
                request.setAttribute(OCTOPUS_CHAIN_NAME, pathPattern);
                return filterChainManager.proxy(originalChain, pathPattern);
            }
        }

        return null;
    }

    /**
     * Returns {@code true} if an incoming request path (the {@code path} argument)
     * matches a configured filter chain path (the {@code pattern} argument), {@code false} otherwise.
     * <p/>
     * Simply delegates to
     * <b><code>{@link PatternMatcher patternMatcher()}.{@link PatternMatcher#matches(String, String) matches(pattern,path)}</code></b>.
     * Subclass implementors should think carefully before overriding this method, as typically a custom
     * {@code PathMatcher} should be configured for custom path matching behavior instead.  Favor OO composition
     * rather than inheritance to limit your exposure to Shiro implementation details which may change over time.
     *
     * @param pattern the pattern to match against
     * @param path    the value to match with the specified {@code pattern}
     * @return {@code true} if the request {@code path} matches the specified filter chain url {@code pattern},
     * {@code false} otherwise.
     */
    protected boolean pathMatches(String pattern, String path) {
        return pathMatcher.matches(pattern, path);
    }

    /**
     * Merely returns
     * <code>WebUtils.{@link WebUtils#getPathWithinApplication(javax.servlet.http.HttpServletRequest) getPathWithinApplication(request)}</code>
     * and can be overridden by subclasses for custom request-to-application-path resolution behavior.
     *
     * @param request the incoming {@code ServletRequest}
     * @return the request's path within the appliation.
     */
    protected String getPathWithinApplication(ServletRequest request) {
        return WebUtils.getPathWithinApplication(WebUtils.toHttp(request));
    }

}
