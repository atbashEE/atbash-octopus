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
package be.atbash.ee.security.octopus.authz.permission.typesafe;

import be.atbash.ee.security.octopus.authz.permission.role.ApplicationRole;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.inject.Typed;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Class capable of converting Enum instances to a {@link ApplicationRole}.
 */
@Typed
//@PublicAPI FIXME Developers should only use <code>new RoleLookup(List<ApplicationRole>, Class<T>)</code>
// See how we can shield this class completely from the developer
public class RoleLookup<T extends Enum<T>> {
    private static final Logger LOGGER = LoggerFactory.getLogger(RoleLookup.class);

    private Map<T, RolePermission> map;  // for holding the mapping between the two

    private Class<T> enumClazz;

    public RoleLookup() {
        // although this bean is excluded, Weld (Glassfish 3.1.2.2) wants it to have a no arg constructor.
    }

    public RoleLookup(List<ApplicationRole> allRoles, Class<T> clazz) {
        enumClazz = clazz;
        map = new EnumMap<>(clazz);
        // map the lookups together
        for (ApplicationRole item : allRoles) {
            T key;

            try {
                key = Enum.valueOf(clazz, item.name());
                map.put(key, new RolePermission(item.name()));
            } catch (IllegalArgumentException e) {
                LOGGER.info("There is no type safe equivalent and CDI Bean for named role " + item.name());
            }
        }
    }

    public RolePermission getRole(T roleName) {
        return map.get(roleName);
    }

    public RolePermission getRole(String roleName) {
        return getRole(Enum.valueOf(enumClazz, roleName));
    }

}

