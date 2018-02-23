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
package be.atbash.ee.security.octopus.authz.annotation;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authz.Combined;
import be.atbash.util.PublicAPI;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the currently executing {@link be.atbash.ee.security.octopus.subject.Subject Subject} to have one of the
 * specified roles. If they do not have the role(s), the method will not be executed and
 * an TODO which exception {@link org.apache.shiro.authz.AuthorizationException AuthorizationException} is thrown.
 * <p/>
 * For example,
 * <p/>
 * <code>&#64;RequiresRoles("aRoleName");<br/>
 * void someMethod();</code>
 * <p/>
 * means <tt>someMethod()</tt> could only be executed by subjects who have been assigned the
 * 'aRoleName' role.
 * <p>
 * The annotation can also be combined with an @Inject annotation to receive a voter capable of verifying the role.
 * <code>
 * &#64;Inject
 * &#64;RequiresRoles("admin")
 * private GenericRoleVoter adminRoleVoter;
 * </code>
 *
 * @see be.atbash.ee.security.octopus.subject.Subject#hasRole(String)
 */
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authz.annotation.RequiresPermissions"})
// Integrated be.c4j.ee.security.realm.OctopusPermissions into this
@PublicAPI
public @interface RequiresRoles {

    /**
     * A single String role name or multiple comma-delimitted role names required in order for the method
     * invocation to be allowed.
     */
    String[] value();

    /**
     * The logical operation for the permission checks in case multiple roles are specified. OR is the default
     */
    Combined combined() default Combined.OR;

    //FIXME We need the equivalent of Class<? extends NamedPermission>[] permission() default {}; on RequiresPermissions
}
