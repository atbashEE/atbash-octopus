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
import be.atbash.ee.security.octopus.sso.core.client.SSOFlow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@ApplicationScoped
@ModuleConfigName("Octopus SSO Server Configuration")
public class OctopusSSOServerConfiguration extends AbstractConfiguration implements ModuleConfig {

    private final Logger LOGGER = LoggerFactory.getLogger(OctopusSSOServerConfiguration.class);

    private static final int COOKIE_TIME_TO_LIVE = 10;
    private static final int ACCESS_TOKEN_TIME_TO_LIVE = 3600;

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
        Pattern pattern = Pattern.compile("^(\\d+)([hdm])$");
        Matcher matcher = pattern.matcher(timeToLive);

        int result = 0;
        if (matcher.matches()) {

            if ("h".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.valueOf(matcher.group(1));
            }
            if ("d".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.valueOf(matcher.group(1)) * 24;
            }
            if ("m".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.valueOf(matcher.group(1)) * 24 * 30;
            }

            if (!(result > 0)) {
                LOGGER.warn("Invalid configuration value for SSO.cookie.timetolive = " + timeToLive + ". Using default of 10h");
                result = COOKIE_TIME_TO_LIVE;
            }

        } else {
            LOGGER.warn("Invalid configuration value for SSO.cookie.timetolive = " + timeToLive + ". Using default of 10h");
            result = COOKIE_TIME_TO_LIVE;
        }
        return result * 60 * 60;  // From hours to seconds
    }

    @ConfigEntry
    public boolean isSSOCookieSecure() {
        return Boolean.valueOf(getOptionalValue("SSO.cookie.secure", "true", String.class));
    }

    @ConfigEntry
    public int getOIDCTokenLength() {
        String propertyValue = getOptionalValue("SSO.token.length", "32", String.class);
        int result;
        try {
            result = Integer.valueOf(propertyValue);
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
        Pattern pattern = Pattern.compile("^(\\d+)([hms])$");
        Matcher matcher = pattern.matcher(timeToLive);

        int result = 0;
        if (matcher.matches()) {

            if ("h".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.valueOf(matcher.group(1)) * 60 * 60;
            }
            if ("m".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.valueOf(matcher.group(1)) * 60;
            }
            if ("s".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.valueOf(matcher.group(1));
            }

            if (!(result > 0)) {
                LOGGER.warn("Invalid configuration value for SSO.access.token.timetolive = " + timeToLive + ". Using default of 1h");
                result = ACCESS_TOKEN_TIME_TO_LIVE;
            }

        } else {
            LOGGER.warn("Invalid configuration value for SSO.access.token.timetolive = " + timeToLive + ". Using default of 10h");
            result = ACCESS_TOKEN_TIME_TO_LIVE;
        }
        return result;
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
}
