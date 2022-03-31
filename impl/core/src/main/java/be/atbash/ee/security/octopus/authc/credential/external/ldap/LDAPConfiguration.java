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
package be.atbash.ee.security.octopus.authc.credential.external.ldap;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.util.StringUtils;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
@ModuleConfigName("Octopus LDAP Support Configuration")
public class LDAPConfiguration extends AbstractConfiguration implements ModuleConfig {

    @ConfigEntry
    public String getLDAPURL() {

        String result = getOptionalValue("ldap.url", String.class);
        if (!StringUtils.hasText(result)) {
            throw new ConfigurationException("Value for configuration parameter 'ldap.url' is required");
        }
        return result;
    }

    @ConfigEntry
    public String getLDAPBindDN() {
        return getOptionalValue("ldap.bindDN", String.class);
    }

    @ConfigEntry(noLogging = true)
    public String getLDAPBindCredential() {
        return getOptionalValue("ldap.bindCredential", String.class);
    }

    @ConfigEntry
    public String getLDAPUserFilter() {
        String result = getOptionalValue("ldap.caller.filter", "(&(uid=%s)(|(objectclass=user)(objectclass=person)(objectclass=inetOrgPerson)(objectclass=organizationalPerson))(!(objectclass=computer)))", String.class);
        if (!StringUtils.hasText(result)) {
            throw new ConfigurationException("Value for configuration parameter 'ldap.user.filter' is required (default is overridden!)");
        }
        return result;
    }

    @ConfigEntry
    public String getLDAPCallerNameAttribute() {
        return getOptionalValue("ldap.caller.name", "cn", String.class);
    }

    @ConfigEntry
    public String getLDAPCallerBaseSearch() {
        return getOptionalValue("ldap.caller.base", "", String.class);
    }

    @ConfigEntry
    public LDAPGroupsNeeded getLDAPGroupsLoaded() {
        String value = getOptionalValue("ldap.groups.loaded", "NO", String.class);
        LDAPGroupsNeeded result;
        try {
            result = LDAPGroupsNeeded.fromValue(value);
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(String.format("Value for configuration parameter 'ldap.groups.loaded' is wrong. Allowed values are 'NO', 'GROUPS' and 'CALLER' but received '%s'", value));
        }
        return result;
    }

    @ConfigEntry
    public String getLDAPGroupFilter() {
        String result = getOptionalValue("ldap.groups.filter", "(&(member=%s)(|(objectclass=group)(objectclass=groupofnames)(objectclass=groupofuniquenames)))", String.class);
        if (!StringUtils.hasText(result)) {
            throw new ConfigurationException("Value for configuration parameter 'ldap.userFilter' is required (default is overridden!)");
        }
        return result;
    }

    @ConfigEntry
    public String getLDAPGroupBaseSearch() {
        return getOptionalValue("ldap.groups.base", "", String.class);
    }

    @ConfigEntry
    public String getLDAPCallerMemberOfAttribute() {
        String result = getOptionalValue("ldap.caller.memberof", "memberOf", String.class);
        if (!StringUtils.hasText(result) && getLDAPGroupsLoaded() != LDAPGroupsNeeded.NO) {
            throw new ConfigurationException("Value for configuration parameter 'ldap.caller.memberof' is required (default is overridden!)");
        }
        return result;
    }

    @ConfigEntry
    public String getLDAPGroupNameAttribute() {
        String result = getOptionalValue("ldap.group.name", "cn", String.class);
        if (!StringUtils.hasText(result) && getLDAPGroupsLoaded() != LDAPGroupsNeeded.NO) {
            throw new ConfigurationException("Value for configuration parameter 'ldap.group.name' is required (default is overridden!)");
        }
        return result;
    }

}
