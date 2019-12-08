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
package be.atbash.ee.security.sso.server.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.sso.core.config.JARMLevel;
import be.atbash.ee.security.octopus.util.duration.PeriodUtil;
import be.atbash.util.StringUtils;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
@ModuleConfigName("Octopus SSO Server Configuration")
public class OctopusSSOServerConfiguration extends AbstractConfiguration implements ModuleConfig {

    @ConfigEntry
    public String getSSOCookieName() {
        return getOptionalValue("SSO.cookie.name", "OctopusSSOToken", String.class);
    }

    /**
     * Returns the value for the cookie in hours
     *
     * @return
     */
    @ConfigEntry
    public int getSSOCookieTimeToLive() {
        String timeToLive = getOptionalValue("SSO.cookie.timetolive", "10h", String.class);

        return TimeConfigUtil.getSecondsFromConfigPattern(timeToLive, "10h", "SSO.cookie.timetolive");

    }

    @ConfigEntry
    public boolean isSSOCookieSecure() {
        return Boolean.parseBoolean(getOptionalValue("SSO.cookie.secure", "true", String.class));
    }

    @ConfigEntry
    public int getOIDCTokenLength() {
        String propertyValue = getOptionalValue("SSO.token.length", "32", String.class);
        int result;
        try {
            result = Integer.parseInt(propertyValue);
        } catch (NumberFormatException e) {
            throw new ConfigurationException("Configuration parameter value 'SSO.token.length' must be numeric and larger then 31");
        }

        if (result < 32) {
            throw new ConfigurationException("Configuration parameter value 'SSO.token.length' must be numeric and larger then 31");
        }
        return result;
    }

    /**
     * Returns the value for the access token time to live in seconds
     *
     * @return
     */
    @ConfigEntry
    public int getSSOAccessTokenTimeToLive() {
        String timeToLive = getOptionalValue("SSO.access.token.timetolive", "1h", String.class);
        return TimeConfigUtil.getSecondsFromConfigPattern(timeToLive, "1h", "SSO.access.token.timetolive");

    }

    public String getSSOEndpointRoot() {
        String ssoEndPointRoot = getOptionalValue("SSO.endpoint.root", "data", String.class);
        return ssoEndPointRoot.replaceAll("^/+", "").replaceAll("/+$", "");
    }

    @ConfigEntry
    public String getOIDCEndpointRateLimit() {
        return getOptionalValue("SSO.rate.limit", "60/1m", String.class);
    }

    @ConfigEntry
    public UserEndpointEncoding getUserEndpointEncoding() {
        String encoding = getOptionalValue("SSO.user.endpoint.encoding", "NONE", String.class);
        UserEndpointEncoding result;
        try {
            result = UserEndpointEncoding.valueOf(encoding);
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException("Valid values for parameter SSO.user.endpoint.encoding are NONE, JWT and JWE");
        }
        return result;
    }

    @ConfigEntry
    public String getScopeForPermissions() {
        return getOptionalValue("SSO.scope.user.permissions", "", String.class);
    }

    @ConfigEntry
    public JARMLevel getJARMLevel() {
        String level = getOptionalValue("SSO.jarm.level", "NONE", String.class);
        JARMLevel result;
        try {
            result = JARMLevel.valueOf(level);
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException("Valid values for parameter 'SSO.jarm.level' are NONE, JWT and JWE");
        }
        return result;
    }

    @ConfigEntry
    public String getJarmSigningKeyId() {
        String kid = getOptionalValue("SSO.jarm.sign.kid", String.class);
        if (StringUtils.isEmpty(kid) && getJARMLevel() != JARMLevel.NONE) {
            throw new ConfigurationException("A valid for parameter 'SSO.jarm.sign.kid' is required when 'SSO.jarm.level' is JWT or JWE");
        }
        return kid;
    }

    @ConfigEntry
    public String getJarmJWTExpirationTime() {
        String expirationExpression = getOptionalValue("SSO.jarm.exp", "2s", String.class);
        if (StringUtils.hasText(expirationExpression)) {
            // Validate the expression
            PeriodUtil.defineSecondsInPeriod(expirationExpression);
        }
        return expirationExpression;
    }
}
