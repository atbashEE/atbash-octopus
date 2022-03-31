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
import be.atbash.ee.security.octopus.WebConstants;
import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.filter.FilterChainResolver;
import be.atbash.ee.security.octopus.mgt.WebSecurityManager;
import be.atbash.ee.security.octopus.realm.OctopusRealm;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.subject.support.WebSubjectContext;
import be.atbash.ee.security.octopus.web.url.SecuredURLReader;
import be.atbash.util.CDIUtils;
import be.atbash.util.Reviewed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

/**
 * Primary Octopus Filter for web applications.
 * <p/>
 * <p>
 * Since the WebFilter is defined with annotations, there is no way to define the order in which the filter needs to be
 * used.
 * If you have other filters that you want to add to your application and want to make sure they are 'secured' as well
 * you can do the following thing
 * TODO Specify how to add a named and/or global filter.
 * </p>
 * This class is now designed as no longer to be able to extend it. The idea is that it just prepares the correct 'Octopus chain of filters'
 * The developer has plenty options to manipulate this 'Octopus chain of filters'.
 */
@Reviewed
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.servlet.ShiroFilter", "org.apache.shiro.web.servlet.AbstractShiroFilter"})
@WebFilter(value = "/*", dispatcherTypes = {DispatcherType.REQUEST, DispatcherType.INCLUDE, DispatcherType.FORWARD, DispatcherType.ERROR, DispatcherType.ASYNC})
public class OctopusFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(OctopusFilter.class);

    // Reference to the security manager used by this filter
    @Inject
    private WebSecurityManager securityManager;

    // Used to determine which chain should handle an incoming request/response
    @Inject
    private FilterChainResolver filterChainResolver;

    @Inject
    private SecuredURLReader securedURLReader;

    @Inject
    private OctopusCoreConfiguration coreConfiguration;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        initFilter(filterConfig.getServletContext());
    }

    /**
     * Initialize the filter by loading the data of the chains for each URL pattern.
     *
     * @param servletContext Context of the container.
     */
    private void initFilter(ServletContext servletContext) {
        securedURLReader.loadData(servletContext);
    }

    /**
     * {@code doFilterInternal} implementation that sets-up, executes, and cleans-up a Octopus-filtered request.
     * <ol>
     * <li> Creates a WebSubject instance based on the specified request/response pair.</li>
     * <li>Executes {@link #executeChain(HttpServletRequest, HttpServletResponse, FilterChain)}
     * method</li>
     * </ol>
     * <p/>
     * The {@link WebSubject#execute(Runnable) execute(Runnable)} call is used as an
     * implementation technique to guarantee proper thread binding and restoration is completed successfully.
     *
     * @param servletRequest  the incoming {@code ServletRequest}
     * @param servletResponse the outgoing {@code ServletResponse}
     * @param chain           the container-provided {@code FilterChain} to execute
     * @throws IOException      if an IO error occurs
     * @throws ServletException if a Throwable other than an IOException
     */
    @Override
    protected void doFilterInternal(final HttpServletRequest servletRequest, final HttpServletResponse servletResponse, final FilterChain chain)
            throws ServletException, IOException {

        Throwable t = null;

        try {

            final WebSubject subject = createWebSubject(servletRequest, servletResponse);

            ThreadContext.bind(subject);

            subject.execute((Callable) () -> {
                executeChain(servletRequest, servletResponse, chain);
                return null;
            });

        } catch (ExecutionException ex) {
            t = ex.getCause();
        } catch (Throwable throwable) {
            t = throwable;
        }

        if (t != null) {
            if (t instanceof ServletException) {
                throw (ServletException) t;
            }
            if (t instanceof IOException) {
                throw (IOException) t;
            }
            //otherwise it's not one of the two exceptions expected by the filter method signature - wrap it in one:
            String msg = "Filtered request failed.";
            throw new ServletException(msg, t);
        }
    }

    private WebSubject createWebSubject(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        WebSubjectContext subjectContext = new WebSubjectContext(CDIUtils.retrieveInstance(OctopusRealm.class));
        subjectContext.setSecurityManager(securityManager);
        subjectContext.setServletRequest(servletRequest);
        subjectContext.setServletResponse(servletResponse);
        return securityManager.createSubject(subjectContext);
    }

    /**
     * Returns the {@code FilterChain} to execute for the given request.
     * <p/>
     * The {@code origChain} argument is the
     * original {@code FilterChain} supplied by the Servlet Container, but it may be modified to provide
     * more behavior by pre-pending further chains according to the Shiro configuration.
     * <p/>
     * This implementation returns the chain that will actually be executed by acquiring the chain from a
     * {@link FilterChainResolver}.  The resolver determines exactly which chain to
     * execute, typically based on URL configuration.  If no chain is returned from the resolver call
     * (returns {@code null}), then the {@code origChain} will be returned by default.
     *
     * @param request   the incoming ServletRequest
     * @param response  the outgoing ServletResponse
     * @param origChain the original {@code FilterChain} provided by the Servlet Container
     * @return the {@link FilterChain} to execute for the given request
     */
    private FilterChain getExecutionChain(HttpServletRequest request, HttpServletResponse response, FilterChain origChain) {
        FilterChain result = origChain;

        FilterChain resolved = filterChainResolver.getChain(request, response, origChain);
        if (resolved != null) {
            log.trace("Resolved a configured FilterChain for the current request.");
            result = resolved;

            if (coreConfiguration.showDebugFor().contains(Debug.FILTER_INFO)) {
                log.info(String.format("Matched the chain %s for the request to %s",
                        request.getAttribute(WebConstants.OCTOPUS_CHAIN_NAME),
                        request.getRequestURI()));
                log.info(String.format("Executing filters %s for the request to %s",
                        request.getAttribute(WebConstants.OCTOPUS_FILTER_NAMES)
                        , request.getRequestURI()));
            }
        } else {
            // TODO Should we have a config parameter to indicate that this happened and write
            // it it the log as info or have some statistics engine?
            log.trace("No FilterChain configured for the current request.  Using the default.");
        }

        return result;
    }

    /**
     * Executes a {@link FilterChain} for the given request.
     * <p/>
     * This implementation first delegates to
     * <code>{@link #getExecutionChain(HttpServletRequest, HttpServletResponse, FilterChain) getExecutionChain}</code>
     * to allow the application's Shiro configuration to determine exactly how the chain should execute.  The resulting
     * value from that call is then executed directly by calling the returned {@code FilterChain}'s
     * {@link FilterChain#doFilter doFilter} method.  That is:
     * <pre>
     * FilterChain chain = {@link #getExecutionChain}(request, response, origChain);
     * chain.{@link FilterChain#doFilter doFilter}(request,response);</pre>
     *
     * @param request   the incoming ServletRequest
     * @param response  the outgoing ServletResponse
     * @param origChain the Servlet Container-provided chain that may be wrapped further by an application-configured
     *                  chain of Filters.
     * @throws IOException      if the underlying {@code chain.doFilter} call results in an IOException
     * @throws ServletException if the underlying {@code chain.doFilter} call results in a ServletException
     */
    protected void executeChain(HttpServletRequest request, HttpServletResponse response, FilterChain origChain)
            throws IOException, ServletException {
        // get the chain of Filters, or the original Chain if no matches found.
        FilterChain chain = getExecutionChain(request, response, origChain);
        chain.doFilter(request, response);
    }

}
