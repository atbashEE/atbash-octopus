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
package be.atbash.ee.security.octopus.subject;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.mgt.DefaultSecurityManager;
import be.atbash.ee.security.octopus.subject.support.DelegatingSubject;

/**
 * Default SubjectFactory implementation that creates {@link DelegatingSubject}
 * instances.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.mgt.DefaultSubjectFactory"})
public class DefaultSubjectFactory {

    public Subject createSubject(SubjectContext context) {
        PrincipalCollection principals = context.resolvePrincipals();
        boolean authenticated = context.resolveAuthenticated();

        return new DelegatingSubject(principals, authenticated, new DefaultSecurityManager(), context.getAuthorizingRealm());
    }

}
