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
package be.atbash.ee.security.octopus.authz.init;

import be.atbash.ee.security.octopus.realm.mgmt.RoleMapperProvider;

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * Loads a {@code LookupProvider} through the serviceLoader mechanism or returns the fallback loader.
 */

public class RoleMapperProviderLoader {

    public <T extends Enum<T>> RoleMapperProvider<T> loadRoleMapperProvider() {
        Iterator<RoleMapperProvider> providerIterator = ServiceLoader.load(RoleMapperProvider.class).iterator();
        if (providerIterator.hasNext()) {
            return providerIterator.next(); // TODO What if there are multiple defined?
        } else {
            return new FallbackRoleMapperProvider();
        }
    }
}
