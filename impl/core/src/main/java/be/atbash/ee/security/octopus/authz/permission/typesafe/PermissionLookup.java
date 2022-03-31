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
package be.atbash.ee.security.octopus.authz.permission.typesafe;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.util.CollectionUtils;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.enterprise.inject.Typed;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Class capable of converting Enum instances to a {@link NamedDomainPermission}. Developers
 */
@Typed
//@PublicAPI FIXME Developers should only use <code>new PermissionLookup(List<NamedDomainPermission>, Class<T>)</code>
// See how we can shield this class completely from the developer
public class PermissionLookup<T extends Enum<T>> {

    private static final Logger LOGGER = LoggerFactory.getLogger(PermissionLookup.class);

    private Map<T, NamedDomainPermission> map;  // for holding the mapping between the two

    private Class<T> enumClazz;

    public PermissionLookup() {
        // although this bean is excluded, Weld (Glassfish 3.1.2.2) wants it to have a no arg constructor.
    }

    public PermissionLookup(List<NamedDomainPermission> allPermissions, Class<T> clazz) {
        if (CollectionUtils.isEmpty(allPermissions)) {
            throw new AtbashIllegalActionException("(OCT-DEV-005) An empty collection is passed for the mapping of an Enum to permissions.");
        }
        enumClazz = clazz;
        map = new EnumMap<>(clazz);
        // map the lookups together
        for (NamedDomainPermission item : allPermissions) {
            T key;
            try {
                key = Enum.valueOf(clazz, item.getName());
                map.put(key, item);
            } catch (IllegalArgumentException e) {
                LOGGER.info("There is no type safe equivalent and CDI Bean for named permission " + item.getName());
            }
        }
    }

    /**
     * Retrieve the {@link NamedDomainPermission} from the enum instance.
     *
     * @param permissionCode
     * @return
     */
    public NamedDomainPermission getPermission(T permissionCode) {
        if (!map.containsKey(permissionCode)) {
            // FIXME Document with exception code
            throw new ConfigurationException(String.format("Permission enum value %s not mapped", permissionCode));
        }
        return map.get(permissionCode);
    }

    /**
     * Retrieve the {@link NamedDomainPermission} from the enum instance String value.
     *
     * @param namedPermission
     * @return
     */
    public NamedDomainPermission getPermission(String namedPermission) {
        return getPermission(Enum.valueOf(enumClazz, namedPermission));
    }

    public boolean containsPermission(String namedPermission) {
        boolean result = true;
        try {
            Enum.valueOf(enumClazz, namedPermission);
        } catch (IllegalArgumentException e) {
            result = false;
        }
        return result;
    }
}

