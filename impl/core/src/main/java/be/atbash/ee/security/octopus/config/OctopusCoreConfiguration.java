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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.exception.ConfigurationException;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.config.logging.StartupLogging;
import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.role.NamedRole;
import be.atbash.ee.security.octopus.cache.CacheManager;
import be.atbash.ee.security.octopus.cache.MemoryConstrainedCacheManager;
import be.atbash.ee.security.octopus.crypto.hash.HashEncoding;
import be.atbash.ee.security.octopus.crypto.hash.HashFactory;
import be.atbash.util.StringUtils;
import be.atbash.util.reflection.CDICheck;
import be.atbash.util.reflection.ClassUtils;
import be.atbash.util.reflection.UnknownClassException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus Core Configuration")
public class OctopusCoreConfiguration extends AbstractConfiguration implements ModuleConfig {

    private Logger logger = LoggerFactory.getLogger(OctopusCoreConfiguration.class);

    private List<Debug> debugValues;

    private Class<? extends Annotation> namedPermissionCheckClass;

    private Class<? extends NamedPermission> namedPermissionClass;

    private Class<? extends Annotation> namedRoleCheckClass;

    private Class<? extends NamedRole> namedRoleClass;

    private Class<? extends Annotation> customCheckClass;

    // Hashing
    @ConfigEntry
    public String getHashAlgorithmName() {
        return getOptionalValue("hashAlgorithmName", "", String.class);
    }

    @ConfigEntry
    public HashEncoding getHashEncoding() {
        String hashEncoding = getOptionalValue("hashEncoding", HashEncoding.HEX.name(), String.class);

        HashEncoding result = HashEncoding.fromValue(hashEncoding);
        if (result == null) {
            throw new ConfigurationException(
                    String.format("The 'hashEncoding' parameter value %s isn't valid. Use 'HEX' or 'BASE64'.", hashEncoding));
        }
        return result;
    }

    @ConfigEntry
    public int getSaltLength() {
        Integer result = getOptionalValue("saltLength", 0, Integer.class);
        if (result != 0 && result < 16) {
            throw new ConfigurationException(
                    String.format("The 'saltLength' parameter value %s isn't valid. it needs to be 16 as minimum.", result));

        }

        return result;
    }

    @ConfigEntry
    public Integer getHashIterations() {
        Integer result = null;
        String hashAlgorithmName = getHashAlgorithmName();
        if (!StringUtils.isEmpty(hashAlgorithmName)) {

            int defaultValue = HashFactory.getInstance().getDefaultHashIterations(hashAlgorithmName);
            String value = getOptionalValue("hashIterations", String.valueOf(defaultValue), String.class);

            try {
                result = Integer.parseInt(value);
                if (result <= 0) {
                    throw new ConfigurationException(String.format("Parameter 'hashIterations' must a a positive integer value : %s", value));
                }
            } catch (NumberFormatException e) {
                throw new ConfigurationException(String.format("Parameter 'hashIterations' must a a positive integer value : %s", e.getLocalizedMessage()));
            }
        }
        return result;
    }

    // CDI bean suffixes
    @ConfigEntry
    public String getPermissionVoterSuffix() {
        return getOptionalValue("voter.suffix.permission", "PermissionVoter", String.class);
    }

    @ConfigEntry
    public String getRoleVoterSuffix() {
        return getOptionalValue("voter.suffix.role", "RoleVoter", String.class);
    }

    @ConfigEntry
    public String getCustomCheckSuffix() {
        return getOptionalValue("voter.suffix.check", "AccessDecisionVoter", String.class);
    }

    // dynamic permissions and roles
    @ConfigEntry
    public Boolean isDynamicAuthorization() {
        return getOptionalValue("authorization.dynamic", Boolean.FALSE, Boolean.class);
    }

    // Named permissions, roles, ...
    @ConfigEntry
    public String getNamedPermission() {
        return getOptionalValue("namedPermission.class", "", String.class);
    }

    @ConfigEntry
    public String getNamedPermissionCheck() {
        // public for the config logging but only used by
        return getOptionalValue("namedPermissionCheck.class", "", String.class);
    }

    @ConfigEntry
    public String getCustomCheck() {
        return getOptionalValue("customCheck.class", "", String.class);
    }

    @ConfigEntry
    public String getNamedRole() {
        return getOptionalValue("namedRole.class", "", String.class);
    }

    @ConfigEntry
    public String getNamedRoleCheck() {
        return getOptionalValue("namedRoleCheck.class", "", String.class);
    }

    public Class<? extends Annotation> getNamedPermissionCheckClass() {
        if (namedPermissionCheckClass == null && getNamedPermissionCheck().length() != 0) {

            try {
                namedPermissionCheckClass = (Class<? extends Annotation>) ClassUtils.forName(getNamedPermissionCheck());
            } catch (UnknownClassException e) {
                logger.error("Class defined in configuration property 'namedPermissionCheck.class' is not found", e);
            }
        }
        return namedPermissionCheckClass;
    }

    public Class<? extends Annotation> getCustomCheckClass() {
        if (customCheckClass == null && getCustomCheck().length() != 0) {

            try {
                customCheckClass = (Class<? extends Annotation>) ClassUtils.forName(getCustomCheck());
            } catch (UnknownClassException e) {
                logger.error("Class defined in configuration property 'customCheck.class' is not found", e);
            }
        }
        return customCheckClass;
    }

    public Class<? extends NamedPermission> getNamedPermissionClass() {
        if (namedPermissionClass == null && getNamedPermission().length() != 0) {
            try {
                namedPermissionClass = (Class<? extends NamedPermission>) ClassUtils.forName(getNamedPermission());
            } catch (UnknownClassException e) {
                logger.error("Class defined in configuration property 'namedPermission.class' is not found", e);
            }
        }
        return namedPermissionClass;
    }

    public Class<? extends Annotation> getNamedRoleCheckClass() {
        if (namedRoleCheckClass == null && getNamedRoleCheck().length() != 0) {

            try {
                namedRoleCheckClass = (Class<? extends Annotation>) ClassUtils.forName(getNamedRoleCheck());
            } catch (UnknownClassException e) {
                logger.error("Class defined in configuration property 'namedRoleCheck.class' is not found", e);
            }
        }
        return namedRoleCheckClass;
    }

    public Class<? extends NamedRole> getNamedRoleClass() {
        if (namedRoleClass == null && getNamedRole().length() != 0) {
            try {
                namedRoleClass = (Class<? extends NamedRole>) Class.forName(getNamedRole());
            } catch (ClassNotFoundException e) {
                logger.error("Class defined in configuration property 'namedRole.class' is not found", e);
            }
        }
        return namedRoleClass;
    }

    // Debug

    @ConfigEntry
    public List<Debug> showDebugFor() {
        if (debugValues == null) {
            // TODO Do we need to make this thread-safe?
            List<Debug> result = new ArrayList<>();
            String value = getOptionalValue("show.debug", "", String.class);
            String[] parts = StringUtils.split(value);
            if (parts != null) {
                for (String part : parts) {
                    String code = part.trim();
                    if (code.length() > 0) {
                        try {
                            Debug debug = Debug.valueOf(code);
                            result.add(debug);
                        } catch (IllegalArgumentException e) {
                            logger.error("Value defined in the show.debug property unknown: {}", part);
                        }
                    }
                }
            }
            debugValues = result;
        }
        return debugValues;
    }

    // Cache
    @ConfigEntry
    public Class<? extends CacheManager> getCacheManagerClass() {
        return getOptionalValue("cacheManager.class", MemoryConstrainedCacheManager.class, Class.class);
    }

    @ConfigEntry
    public boolean isAuthenticationCachingEnabled() {
        return getOptionalValue("cache.authentication.activate", false, Boolean.class);
    }

    // CDI Interceptor / interdyn
    @ConfigEntry
    public boolean getCDIInterceptorActive() {
        Boolean interceptorEnabled = getOptionalValue("cdi.interceptor.enabled", Boolean.class);
        return interceptorEnabled != null && interceptorEnabled;
    }

    @ConfigEntry
    public String getCDIInterceptorConfigFile() {
        return getOptionalValue("cdi.interceptor.configfile", "classpath:octopusInterceptor.config", String.class);
    }

    // Java SE Support + Used in CDI Extension
    private static OctopusCoreConfiguration INSTANCE;

    private static final Object LOCK = new Object();

    public static OctopusCoreConfiguration getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new OctopusCoreConfiguration();
                    if (!CDICheck.withinContainer()) {
                        StartupLogging.logConfiguration(INSTANCE);
                    }
                }
            }
        }
        return INSTANCE;
    }
}
