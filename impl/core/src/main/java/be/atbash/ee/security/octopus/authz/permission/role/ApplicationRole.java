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
package be.atbash.ee.security.octopus.authz.permission.role;

import be.atbash.util.PublicAPI;
import be.atbash.util.Reviewed;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;

/**
 * A role of the user, an implementation of {@link NamedRole}. It is the preferred way of passing a Role to the Octopus System (through the
 * {@link be.atbash.ee.security.octopus.realm.AuthorizationInfoBuilder})
 */
@PublicAPI
@Reviewed
public class ApplicationRole implements NamedRole {

    private final String name;

    public ApplicationRole(String name) {
        if (StringUtils.isEmpty(name)) {
            throw new AtbashIllegalActionException("(OCT-DEV-010) The name can't be empty for a ApplicationRole");
        }
        this.name = name;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ApplicationRole)) {
            return false;
        }

        ApplicationRole that = (ApplicationRole) o;

        return name.equals(that.name);
    }

    @Override
    public final int hashCode() {
        return name.hashCode();
    }
}
