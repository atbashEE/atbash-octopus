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
package be.atbash.ee.security.octopus.filter.authz;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.filter.authc.AbstractUserFilter;
import be.atbash.ee.security.octopus.filter.mgt.FilterChainManager;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.ee.security.octopus.web.servlet.AbstractFilter;
import be.atbash.util.StringUtils;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@ApplicationScoped
public class JSFAccessDeniedHandler implements AccessDeniedHandler {

    @Inject
    private OctopusJSFConfiguration jsfConfiguration;

    @Inject
    private FilterChainManager filterChainManager;

    private AbstractUserFilter userFilter;

    @PostConstruct
    public void init() {
        AbstractFilter filter = filterChainManager.getFilter(jsfConfiguration.getDefaultUserFilter());
        if (!(filter instanceof AbstractUserFilter)) {
            throw new ConfigurationException(String.format("(OCT-DEV-???) The filter defined with 'user.filter.default' must be an instance of AbstractUserFilter. %s is not of the correct type", jsfConfiguration.getDefaultUserFilter()));
        }
        userFilter = (AbstractUserFilter) filter;
    }

    @Override
    public boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {

        WebSubject subject = SecurityUtils.getSubject();
        // If the subject isn't identified, redirect to login URL
        if (subject.getPrincipal() == null || !(subject.isAuthenticated() || subject.isRemembered())) {
            userFilter.saveRequestAndRedirectToLogin(request, response);
        } else {
            // If subject is known but not authorized, redirect to the unauthorized URL if there is one
            // If no unauthorized URL is specified, just return an unauthorized HTTP status code
            String unauthorizedUrl = jsfConfiguration.getUnauthorizedExceptionPage();
            // - ensure that redirect _or_ error code occurs - both cannot happen due to response commit:
            if (StringUtils.hasText(unauthorizedUrl)) {
                WebUtils.issueRedirect(request, response, unauthorizedUrl);
            } else {
                WebUtils.toHttp(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }
        return false;

    }
}
