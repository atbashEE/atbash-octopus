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
package be.atbash.ee.security.octopus.sso.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.sso.core.client.SSOFlow;
import be.atbash.util.StringUtils;
import com.nimbusds.jose.util.Base64;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

@ApplicationScoped
@ModuleConfigName("Octopus SSO Client Configuration")
public class OctopusSSOClientConfiguration extends AbstractConfiguration implements ModuleConfig {

    @ConfigEntry
    public String getLoginPage() {
        return getSSOServer() + "/octopus/sso/authenticate";
    }

    @ConfigEntry
    public String getLogoutPage() {
        return getSSOServer() + "/octopus/sso/logout";
    }

    @Inject
    @ConfigProperty(name = "unauthorizedExceptionPage", defaultValue = "/unauthorized.xhtml")
    private String unauthorizedPage;

    @ConfigEntry
    public String getUnauthorizedExceptionPage() {
        return unauthorizedPage;
    }
    // TODO The above parameter is duplicated, Can this be avoided?

    @ConfigEntry
    public String getSSOServer() {
        // FIXME Also support SSO.server. Make same as KeyCloak (verify)
        String result = getOptionalValue("SSO.octopus.server", String.class);
        if (StringUtils.isEmpty(result)) {
            throw new ConfigurationException("A value for 'Octopus.SSO.server' is required.");
        }
        return result;
    }

    @ConfigEntry
    public String getSSOApplication() {
        return getOptionalValue("SSO.application", "", String.class);
    }

    @ConfigEntry
    public String getSSOApplicationSuffix() {
        return getOptionalValue("SSO.application.suffix", "", String.class);
    }

    @ConfigEntry
    public String getSSOClientId() {
        String ssoClientId = defineConfigValue("SSO.clientId");
        if (StringUtils.isEmpty(ssoClientId)) {
            throw new ConfigurationException("Value for {SSO.application}SSO.clientId parameter is empty");
        }
        return ssoClientId;
    }

    @ConfigEntry(noLogging = true)
    public byte[] getSSOClientSecret() {
        String ssoClientSecret = defineConfigValue("SSO.clientSecret");
        if (getSSOType() == SSOFlow.AUTHORIZATION_CODE && StringUtils.isEmpty(ssoClientSecret)) {
            throw new ConfigurationException("Value for {SSO.application}SSO.clientSecret parameter is empty");
        }
        if (ssoClientSecret != null && !ssoClientSecret.trim().isEmpty()) {
            byte[] result = new Base64(ssoClientSecret).decode();
            if (result.length < 32) {
                throw new ConfigurationException("value for {SSO.application}SSO.clientSecret must be at least 32 byte (256 bit)");
            }
            return result;
        } else {
            return new byte[0];
        }
    }

    @ConfigEntry(noLogging = true)
    public byte[] getSSOIdTokenSecret() {
        String tokenSecret = defineConfigValue("SSO.idTokenSecret");
        if (StringUtils.isEmpty(tokenSecret)) {
            throw new ConfigurationException("Value for {SSO.application}SSO.idTokenSecret parameter is empty");
        }

        byte[] result = new Base64(tokenSecret).decode();

        if (result.length < 32) {
            throw new ConfigurationException("value for {SSO.application}SSO.idTokenSecret must be at least 32 byte (256 bit)");
        }
        return result;
    }

    @ConfigEntry
    public SSOFlow getSSOType() {
        String ssoFlowParameter = defineConfigValue("SSO.flow");
        SSOFlow ssoFlow = SSOFlow.defineFlow(ssoFlowParameter);
        if (ssoFlow == null) {
            throw new ConfigurationException("Value for {SSO.application}SSO.flow parameter is invalid. Must be 'token' or 'code'");
        }
        return ssoFlow;
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

    @ConfigEntry
    public String getAccessPermission() {
        return getOptionalValue("SSO.application.permission.access", "", String.class);
    }

}
