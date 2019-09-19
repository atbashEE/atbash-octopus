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
package be.atbash.ee.security.octopus.filter;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.util.PatternMatcher;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.HashMap;
import java.util.Map;

import static be.atbash.ee.security.octopus.filter.FilterChainResolver.OCTOPUS_CHAIN_NAME;

/**
 * <p>Base class for Filters that will process only specified paths and allow all others to pass through.</p>
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.filter.PathMatchingFilter", "org.apache.shiro.web.filter.PathConfigProcessor"})
public abstract class PathMatchingFilter extends AdviceFilter {

    private static final String PATH_CONFIG = "octopus.pathConfig";

    /**
     * Log available to this class only
     */
    private static final Logger log = LoggerFactory.getLogger(PathMatchingFilter.class);

    /**
     * PatternMatcher used in determining which paths to react to for a given request.
     */

    @Inject
    private PatternMatcher pathMatcher;

    /**
     * A collection of path-to-config entries where the key is a path which this filter should process and
     * the value is the (possibly null) configuration element specific to this Filter for that specific path.
     * <p/>
     * <p>To put it another way, the keys are the paths (urls) that this Filter will process.
     * <p>The values are filter-specific data that this Filter should use when processing the corresponding
     * key (path).  The values can be null if no Filter-specific config was specified for that url.
     */
    protected Map<String, String[]> appliedPaths = new HashMap<>();

    /**
     * Processes the specified {@code config}, unique to the given {@code path}, and returns the Filter that should
     * execute for that path/config combination.
     * <p/>
     * Split any comma-delimited values that might be found in the <code>config</code> argument and sets the resulting
     * <code>String[]</code> array on the <code>appliedPaths</code> internal Map.
     * <p/>
     * That is:
     * <pre><code>
     * String[] values = null;
     * if (config != null) {
     *     values = split(config);
     * }
     * <p/>
     * this.{@link #appliedPaths appliedPaths}.put(path, values);
     * </code></pre>
     *
     * @param path   the application context path to match for executing this filter.
     * @param config the specified config for <em>this particular filter only</em> for the given <code>path</code>
     * @return this configured filter.
     */
    public Filter processPathConfig(String path, String config) {
        String[] values = null;
        if (config != null) {
            values = StringUtils.split(config);
        }

        if (requiresPathConfiguration() && (values == null || values.length == 0)) {
            String msg = String.format("(E0013) Error : chainSpecificFilterConfig is required for filter '%s'", this.getClass().getName());
            throw new ConfigurationException(msg);

        }
        appliedPaths.put(path, values);
        return this;
    }

    /**
     * Returns the context path within the application based on the specified <code>request</code>.
     * <p/>
     * This implementation merely delegates to
     * {@link WebUtils#getPathWithinApplication(javax.servlet.http.HttpServletRequest) WebUtils.getPathWithinApplication(request)},
     * but can be overridden by subclasses for custom logic.
     *
     * @param request the incoming <code>ServletRequest</code>
     * @return the context path within the application.
     */
    protected String getPathWithinApplication(ServletRequest request) {
        return WebUtils.getPathWithinApplication(WebUtils.toHttp(request));
    }

    /**
     * Returns <code>true</code> if the incoming <code>request</code> matches the specified <code>path</code> pattern,
     * <code>false</code> otherwise.
     * <p/>
     * The default implementation acquires the <code>request</code>'s path within the application and determines
     * if that matches:
     * <p/>
     * <code>String requestURI = {@link #getPathWithinApplication(ServletRequest) getPathWithinApplication(request)};<br/>
     * return {@link #pathsMatch(String, String) pathsMatch(path,requestURI)}</code>
     *
     * @param path    the configured url pattern to check the incoming request against.
     * @param request the incoming ServletRequest
     * @return <code>true</code> if the incoming <code>request</code> matches the specified <code>path</code> pattern,
     * <code>false</code> otherwise.
     */
    protected boolean pathsMatch(String path, ServletRequest request) {
        String requestURI = getPathWithinApplication(request);
        log.trace("Attempting to match pattern '{}' with current requestURI '{}'...", path, requestURI);
        return pathsMatch(path, requestURI);
    }

    /**
     * Returns <code>true</code> if the <code>path</code> matches the specified <code>pattern</code> string,
     * <code>false</code> otherwise.
     * <p/>
     * Simply delegates to
     * <b><code>this.pathMatcher.{@link PatternMatcher#matches(String, String) matches(pattern,path)}</code></b>,
     * but can be overridden by subclasses for custom matching behavior.
     *
     * @param pattern the pattern to match against
     * @param path    the value to match with the specified <code>pattern</code>
     * @return <code>true</code> if the <code>path</code> matches the specified <code>pattern</code> string,
     * <code>false</code> otherwise.
     */
    protected boolean pathsMatch(String pattern, String path) {
        return pathMatcher.matches(pattern, path);
    }

    /**
     * Implementation that handles path-matching behavior before a request is evaluated.  If the path matches and
     * the filter
     * {@link #isEnabled(ServletRequest, ServletResponse, String) isEnabled} for
     * that path/config, the request will be allowed through via the result from
     * {@link #onPreHandle(ServletRequest, ServletResponse) onPreHandle}.  If the
     * path does not match or the filter is not enabled for that path, this filter will allow passthrough immediately
     * to allow the {@code FilterChain} to continue executing.
     * <p/>
     * In order to retain path-matching functionality, subclasses should not override this method if at all
     * possible, and instead override
     * {@link #onPreHandle(ServletRequest, ServletResponse) onPreHandle} instead.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @return {@code true} if the filter chain is allowed to continue to execute, {@code false} if a subclass has
     * handled the request explicitly.
     * @throws Exception if an error occurs
     */
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {

        String pathKeyName = (String) request.getAttribute(OCTOPUS_CHAIN_NAME);
        if (StringUtils.isEmpty(pathKeyName)) {
            // There is not passing through the Octopus filters and thus we just allow that the chain continues.
            // In fact, we should never be in this case, all (Octopus) filters descending from PathMatchingFilter should have this attribute.
            if (log.isTraceEnabled()) {
                log.trace("appliedPaths property is null or empty.  This Filter will passthrough immediately.");
            }
            return true;
        }
        String[] config = appliedPaths.get(pathKeyName);
        request.setAttribute(PATH_CONFIG, config);

        return isFilterChainContinued(request, response, pathKeyName);
    }

    protected String[] getPathConfig(ServletRequest request) {
        return (String[]) request.getAttribute(PATH_CONFIG);
    }

    /**
     * Simple method to abstract out logic from the preHandle implementation.
     */
    private boolean isFilterChainContinued(ServletRequest request, ServletResponse response,
                                           String path) throws Exception {

        if (isEnabled(request, response, path)) {
            if (log.isTraceEnabled()) {
                String[] pathConfig = getPathConfig(request);
                log.trace("Filter '{}' is enabled for the current request under path '{}' with config [{}].  " +
                                "Delegating to subclass implementation for 'onPreHandle' check.",
                        getName(), path, pathConfig);
            }
            //The filter is enabled for this specific request, so delegate to subclass implementations
            //so they can decide if the request should continue through the chain or not:
            return onPreHandle(request, response);
        }

        if (log.isTraceEnabled()) {
            String[] pathConfig = getPathConfig(request);
            log.trace("Filter '{}' is disabled for the current request under path '{}' with config [{}].  " +
                            "The next element in the FilterChain will be called immediately.",
                    getName(), path, pathConfig);
        }
        //This filter is disabled for this specific request,
        //return 'true' immediately to indicate that the filter will not process the request
        //and let the request/response to continue through the filter chain:
        return true;
    }

    /**
     * This default implementation always returns {@code true} and should be overridden by subclasses for custom
     * logic if necessary.
     *
     * @param request     the incoming ServletRequest
     * @param response    the outgoing ServletResponse
     * @return {@code true} if the request should be able to continue, {@code false} if the filter will
     * handle the response directly.
     * @throws Exception if an error occurs
     * @see #isEnabled(ServletRequest, ServletResponse, String)
     */
    protected boolean onPreHandle(ServletRequest request, ServletResponse response) throws Exception {
        return true;
    }

    /**
     * Path-matching version of the parent class's
     * {@link #isEnabled(ServletRequest, ServletResponse)} method, but additionally allows
     * for inspection of any path-specific configuration values corresponding to the specified request.  Subclasses
     * may wish to inspect this additional mapped configuration to determine if the filter is enabled or not.
     * <p/>
     * This method's default implementation ignores the {@code path} arguments and merely
     * returns the value from a call to {@link #isEnabled(ServletRequest, ServletResponse)}.
     * It is expected that subclasses override this method if they need to perform enable/disable logic for a specific
     * request based on any path-specific config for the filter instance.
     *
     * @param request    the incoming servlet request
     * @param response   the outbound servlet response
     * @param path       the path matched for the incoming servlet request that has been configured.
     * @return {@code true} if this filter should filter the specified request, {@code false} if it should let the
     * request/response pass through immediately to the next element in the {@code FilterChain}.
     * @throws Exception in the case of any error
     */
    @SuppressWarnings({"UnusedParameters"})
    protected boolean isEnabled(ServletRequest request, ServletResponse response, String path)
            throws Exception {
        return isEnabled(request, response);
    }

    /**
     * Determines if the filter requires some Path Configuration like for example `NamedPermission[permission1]`. Since without
     * the brackets, or empty value in between, the filter can't do much.
     *
     * @return false by default but can be overridden by descendant classes.
     */
    protected boolean requiresPathConfiguration() {
        return false;
    }
}
