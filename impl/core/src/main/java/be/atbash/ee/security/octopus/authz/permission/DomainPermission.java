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
package be.atbash.ee.security.octopus.authz.permission;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.util.StringUtils;

import java.util.Set;

/**
 * Provides a base Permission class from which type-safe/domain-specific subclasses may extend.  Can be used
 * as a base class for JPA/Hibernate persisted permissions that wish to store the parts of the permission string
 * in separate columns (e.g. 'domain', 'actions' and 'targets' columns), which can be used in querying
 * strategies.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authz.permission.DomainPermission"})
//@PublicAPI
// FIXME Integrate NamedPermission into this class. Because we should have only NamedPermissions and since
//Class based permissions are based on this class, we need the NamedPermission interface here also!
public class DomainPermission extends WildcardPermission {

    private String domain;
    private Set<String> actions;
    private Set<String> targets;

    /**
     * Creates a domain permission with *all* actions for *all* targets;
     */

    public DomainPermission() {
        setParts(getDomain(getClass()));
        defineProperties();

    }

    public DomainPermission(String actions) {
        encodeParts(getDomain(getClass()), actions, null);
        defineProperties();
    }

    public DomainPermission(String actions, String targets) {
        encodeParts(getDomain(getClass()), actions, targets);
        defineProperties();
    }

    // FIXME Usage
    protected DomainPermission(Set<String> actions, Set<String> targets) {
        setParts(getDomain(getClass()), actions, targets);
        defineProperties();
    }

    protected void defineProperties() {
        this.domain = getParts().get(0).iterator().next();
        if (getParts().size() > 1) {
            this.actions = getParts().get(1);
        }
        if (getParts().size() > 2) {
            this.targets = getParts().get(2);
        }
    }

    private void encodeParts(String domain, String actions, String targets) {
        if (!StringUtils.hasText(domain)) {
            throw new IllegalArgumentException("domain argument cannot be null or empty.");
        }
        StringBuilder sb = new StringBuilder(domain);

        if (!StringUtils.hasText(actions)) {
            if (StringUtils.hasText(targets)) {
                sb.append(PART_DIVIDER_TOKEN).append(WILDCARD_TOKEN);
            }
        } else {
            sb.append(PART_DIVIDER_TOKEN).append(actions);
        }
        if (StringUtils.hasText(targets)) {
            sb.append(PART_DIVIDER_TOKEN).append(targets);
        }
        setParts(sb.toString());
    }

    protected void setParts(String domain, Set<String> actions, Set<String> targets) {
        String actionsString = StringUtils.toDelimitedString(SUBPART_DIVIDER_TOKEN, actions);
        String targetsString = StringUtils.toDelimitedString(SUBPART_DIVIDER_TOKEN, targets);
        encodeParts(domain, actionsString, targetsString);
    }

    protected String getDomain(Class<? extends DomainPermission> clazz) {
        String domain = clazz.getSimpleName().toLowerCase();
        //strip any trailing 'permission' text from the name (as all subclasses should have been named):
        int index = domain.lastIndexOf("permission");
        if (index != -1) {
            domain = domain.substring(0, index);
        }
        return domain;
    }

    public String getDomain() {
        return domain;
    }

    protected void setDomain(String domain) {
        if (this.domain != null && this.domain.equals(domain)) {
            return;
        }
        this.domain = domain;
        setParts(domain, actions, targets);
    }

    public Set<String> getActions() {
        return actions;
    }

    protected void setActions(Set<String> actions) {
        if (this.actions != null && this.actions.equals(actions)) {
            return;
        }
        this.actions = actions;
        setParts(domain, actions, targets);
    }

    public Set<String> getTargets() {
        return targets;
    }

    protected void setTargets(Set<String> targets) {
        if (this.targets != null && this.targets.equals(targets)) {
            return;
        }
        this.targets = targets;
        setParts(domain, actions, targets);
    }

}
