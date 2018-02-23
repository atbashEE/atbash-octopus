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
package be.atbash.ee.security.octopus.authz.permission;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.util.CollectionUtils;
import be.atbash.util.PublicAPI;
import be.atbash.util.StringUtils;

/**
 * Instead of creating a class for each permission, we can create an instance of this class for each Permission.
 * TODO Javadoc
 */
@PublicAPI
public class NamedDomainPermission extends DomainPermission implements NamedPermission {

    private String name;

    public NamedDomainPermission(String someName, String someDomain, String actions, String targets) {
        super(actions, targets);
        setDomain(someDomain);
        if (StringUtils.isEmpty(someName)) {
            // FIXME Document with exception code
            throw new ConfigurationException("Named permission can't be null or empty");
        }
        name = someName;
    }

    /**
     * When we need to create the the NamedDomainPermission based on a name and a wildcardString. For example Department:create:* as wildcard string.
     *
     * @param someName
     * @param wildcardString
     */
    public NamedDomainPermission(String someName, String wildcardString) {
        name = someName;
        //setParts(wildcardString.replaceAll(" ", ""));
        setParts(wildcardString);

        defineProperties();
    }

    public String getName() {
        return name;
    }

    @Override
    public String name() {
        return name;
    }

    public String getWildcardNotation() {
        StringBuilder result = new StringBuilder();
        result.append(getDomain());
        if (!CollectionUtils.isEmpty(getActions())) {
            result.append(PART_DIVIDER_TOKEN).append(StringUtils.join(getActions().iterator(), SUBPART_DIVIDER_TOKEN));
            if (!CollectionUtils.isEmpty(getTargets())) {
                result.append(PART_DIVIDER_TOKEN).append(StringUtils.join(getTargets().iterator(), SUBPART_DIVIDER_TOKEN));
            }
        }
        return result.toString();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof NamedDomainPermission)) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }

        NamedDomainPermission that = (NamedDomainPermission) o;

        return name.equals(that.name);

    }

    @Override
    public final int hashCode() {
        int result = super.hashCode();
        result = 31 * result + name.hashCode();
        return result;
    }
}
