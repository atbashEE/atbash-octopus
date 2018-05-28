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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus JSF Configuration")
public class OctopusJSFConfiguration implements ModuleConfig {

    @Inject
    @ConfigProperty(name = "user.filter.default", defaultValue = "user")
    private String defaultUserFilter;

    @Inject
    @ConfigProperty(name = "loginPage", defaultValue = "/login.xhtml")
    private String loginPage;

    @Inject
    @ConfigProperty(name = "logoutPage", defaultValue = "/")
    private String logoutPage;

    @Inject
    @ConfigProperty(name = "logoutFilter.postOnly", defaultValue = "false")
    private boolean logoutFilterPostOnly;

    @Inject
    @ConfigProperty(name = "allowPostAsSavedRequest", defaultValue = "true")
    private boolean allowPostAsSavedRequest;

    @Inject
    @ConfigProperty(name = "unauthorizedExceptionPage", defaultValue = "/unauthorized.xhtml")
    private String unauthorizedPage;

    @Inject
    @ConfigProperty(name = "primefaces.mobile.exclusion", defaultValue = "false")
    private boolean primeFacesMobileExclusion;

    @Inject
    @ConfigProperty(name = "single.logout", defaultValue = "false")
    private boolean singleLogout;

    @ConfigEntry()
    public String getLoginPage() {
        return loginPage;
    }

    @ConfigEntry
    public String getLogoutPage() {
        return logoutPage;
    }

    @ConfigEntry
    public boolean getLogoutFilterPostOnly() {
        return logoutFilterPostOnly;
    }

    @ConfigEntry
    public boolean getPostIsAllowedSavedRequest() {
        return allowPostAsSavedRequest;
    }

    /**
     * Returns the URL to which users should be redirected if they are denied access to an underlying path or resource,
     * or {@code null} if a raw {@link HttpServletResponse#SC_UNAUTHORIZED} response should be issued (401 Unauthorized).
     * <p/>
     *
     * @return the URL to which users should be redirected if they are denied access to an underlying path or resource,
     * or {@code null} if a raw {@link HttpServletResponse#SC_UNAUTHORIZED} response should be issued (401 Unauthorized).
     */
    @ConfigEntry
    public String getUnauthorizedExceptionPage() {
        return unauthorizedPage;
    }

    @ConfigEntry
    public boolean isExcludePrimeFacesMobile() {
        return primeFacesMobileExclusion;
    }

    @ConfigEntry
    public boolean isSingleLogout() {
        // TODO We should also support single logout on a individual base, meaning
        // By default no single.logout but clicking on the SSO logout  button, performs also the SSO logout.
        // Subject.ssoLogout() ?
        return singleLogout;
    }

    @ConfigEntry
    public String getDefaultUserFilter() {
        return defaultUserFilter;
    }
}
