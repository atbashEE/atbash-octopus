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
package be.atbash.ee.security.octopus.sso.client.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.config.logging.StartupLogging;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.util.StringUtils;
import be.atbash.util.reflection.CDICheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import java.util.Base64;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus Server Configuration")
public class OctopusSSOServerClientConfiguration extends AbstractConfiguration implements ModuleConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(OctopusSSOServerClientConfiguration.class);

    @ConfigEntry
    public String getSSOApplication() {
        return getOptionalValue("SSO.application", "", String.class);
    }

    @ConfigEntry
    public String getSSOApplicationSuffix() {
        return getOptionalValue("SSO.application.suffix", "", String.class);
    }

    @ConfigEntry
    public String getOctopusSSOServer() {
        String result = getOptionalValue("SSO.octopus.server", "", String.class);
        // TODO Remove trailing / as it will result in Unexpected Issuer
        // FIXME Also support SSO.server. Make same as KeyCloak (verify)
        if (result == null || result.trim().isEmpty()) {
            throw new ConfigurationException("Value for SSO.octopus.server parameter is empty.");
        }
        return result;
    }

    @ConfigEntry
    public String getUserInfoEndpoint() {
        return getOctopusSSOServer() + "/" + getSSOEndpointRoot() + "/octopus/sso/user";

    }

    @ConfigEntry
    public String getLogoutPage() {
        return getOctopusSSOServer() + "/octopus/sso/logout";
    }

    @ConfigEntry
    public String getTokenEndpoint() {

        return getOctopusSSOServer() + "/octopus/sso/token";

    }

    @ConfigEntry
    public String getSSOEndpointRoot() {
        String ssoEndPointRoot = getOptionalValue("SSO.endpoint.root", "data", String.class);
        return ssoEndPointRoot.replaceAll("^/+", "").replaceAll("/+$", "");
    }

    @ConfigEntry
    public String getSSOClientId() {
        String ssoClientId = defineConfigValue("SSO.clientId");
        if (ssoClientId.trim().isEmpty()) {
            throw new ConfigurationException("Value for {SSO.application}SSO.clientId parameter is empty");
        }
        return ssoClientId;
    }

    @ConfigEntry
    public byte[] getSSOClientSecret() {
        String ssoClientSecret = defineConfigValue("SSO.clientSecret");
        if (StringUtils.hasText(ssoClientSecret)) {
            byte[] result = Base64.getUrlDecoder().decode(ssoClientSecret);
            if (result.length < 32) {
                throw new ConfigurationException("value for {SSO.application}SSO.clientSecret must be at least 32 byte (256 bit)");
            }
            return result;
        } else {
            throw new ConfigurationException("value for {SSO.application}SSO.clientSecret must be at least 32 byte (256 bit)");
        }
    }

    @ConfigEntry
    public byte[] getSSOIdTokenSecret() {
        String tokenSecret = defineConfigValue("SSO.idTokenSecret");
        if (StringUtils.isEmpty(tokenSecret)) {
            throw new ConfigurationException("Value for {SSO.application}SSO.idTokenSecret parameter is empty");
        }

        byte[] result = Base64.getUrlDecoder().decode(tokenSecret);

        if (result.length < 32) {
            throw new ConfigurationException("value for {SSO.application}SSO.idTokenSecret must be at least 32 byte (256 bit)");
        }
        return result;
    }

    @ConfigEntry
    public String getSSOScopes() {
        String result = defineConfigValue("SSO.scopes");
        if (result == null) {
            result = "";
        }
        return result;
    }

    private String defineConfigValue(String configParameter) {
        String configKeyPrefix = getSSOApplication() + getSSOApplicationSuffix();
        String result = getOptionalValue(configKeyPrefix + '.' + configParameter, "", String.class);
        if (result.trim().isEmpty()) {
            result = getOptionalValue(configParameter, "", String.class);
        }
        return result;
    }

    // Java SE Support
    private static OctopusSSOServerClientConfiguration INSTANCE;

    private static final Object LOCK = new Object();

    public static OctopusSSOServerClientConfiguration getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new OctopusSSOServerClientConfiguration();
                    if (!CDICheck.withinContainer()) {
                        StartupLogging.logConfiguration(INSTANCE);
                    }
                }
            }
        }
        return INSTANCE;
    }

}
