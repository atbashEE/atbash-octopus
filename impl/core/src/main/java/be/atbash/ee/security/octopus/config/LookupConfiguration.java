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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.ee.security.octopus.authz.permission.typesafe.RoleLookup;
import be.atbash.util.reflection.ClassUtils;

/**
 *
 */

public class LookupConfiguration extends AbstractConfiguration {

    public RoleLookup<?> getRoleLookup() {
        Class lookupClass = getOptionalValue("roleLookup.class", null, Class.class);
        if (lookupClass != null) {
            return ClassUtils.newInstance(lookupClass);
        } else {
            return null;
        }
    }

}
