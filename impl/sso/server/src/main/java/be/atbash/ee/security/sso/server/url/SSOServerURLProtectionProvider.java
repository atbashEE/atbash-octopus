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
package be.atbash.ee.security.sso.server.url;

import be.atbash.ee.security.octopus.web.url.ProgrammaticURLProtectionProvider;
import be.atbash.ee.security.octopus.web.url.URLProtectionProviderOrder;
import be.atbash.ee.security.sso.server.config.OctopusSSOServerConfiguration;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.LinkedHashMap;

/**
 *
 */
@ApplicationScoped
@URLProtectionProviderOrder(100)
public class SSOServerURLProtectionProvider implements ProgrammaticURLProtectionProvider {

    @Inject
    private OctopusSSOServerConfiguration configuration;

    @Override
    public LinkedHashMap<String, String> getURLEntriesToAdd() {
        LinkedHashMap<String, String> result = new LinkedHashMap<>();  // Keep order of insertion
        // For the rest endpoints retrieving user info / permissions
        result.put("/" + configuration.getSSOEndpointRoot() + "/octopus/sso/permissions/*", "noSessionCreation, anon");
        result.put("/" + configuration.getSSOEndpointRoot() + "/octopus/**", "noSessionCreation, ssoFilter"); // FIXME Is this correct and not to 'wide' (see also last pattern)

        // URL related to OpenId Connect
        result.put("/octopus/sso/logout", "ssoLogout");  // So we need a user (from cookie) or accessToken, to be able to logout

        result.put("/octopus/sso/authenticate", "oidcFilter");
        result.put("/octopus/sso/token", String.format("rate[%s], oidcFilter", configuration.getOIDCEndpointRateLimit()));
        result.put("/octopus/testAuthentication", "anon");  // But the SSOCookieRemembermeManager does his job :)
        result.put("/octopus/alive", "rate[20/1s], anon");  // 20 checks / sec !!
        result.put("/octopus/**", "none");

        return result;
    }
}
