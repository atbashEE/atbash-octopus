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
import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.util.PublicAPI;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * <p>
 * Requires the current executor's Subject to imply a particular permission in
 * order to execute the annotated method.  If the executor's associated
 * {@link be.atbash.ee.security.octopus.subject.Subject Subject} determines that the
 * executor does not imply the specified permission, the method will not be executed.
 * </p>
 * <p>
 * <p>For example, this declaration:
 * <p/>
 * <code>&#64;RequiresPermissions( {"file:read", "write:aFile.txt"} )<br/>
 * void someMethod();</code>
 * <p/>
 * indicates the current user must be able to  <tt>read</tt> or <tt>write</tt>
 * to the file <tt>aFile.txt</tt> in order for the <tt>someMethod()</tt> to execute, otherwise
 * an ??? TODO {@link org.apache.shiro.authz.AuthorizationException AuthorizationException} will be thrown.
 * <p/>
 * The annotation can also be combined with an @Inject annotation to receive a voter capable of verifying the permission.
 * <code>
 * &#64;Inject
 * &#64;RequiresPermissions("demo:*:*")
 * private GenericPermissionVoter demoPermissionVoter;
 * </code>
 *
 * @see be.atbash.ee.security.octopus.subject.Subject#checkPermission
 */
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authz.annotation.RequiresPermissions"})
// Integrated be.c4j.ee.security.realm.OctopusPermissions into this
@PublicAPI
public @interface RequiresPermissions {

    /**
     * The permission string which will be passed to {@link be.atbash.ee.security.octopus.subject.Subject#isPermitted(String)}
     * to determine if the user is allowed to invoke the code protected by this annotation.
     */
    String[] value() default {""};  // FIXME this has now a default value so no longer required to define it.
    // FIXME Make sure value or permission is defined.

    /**
     * The logical operation for the permission checks in case multiple permissions are specified. OR is the default
     */
    Combined combined() default Combined.OR;

    // FIXME Create support for those class based Permissions like PrinterPermission extends DomainPermission
    Class<? extends NamedPermission>[] permission() default {};
}

