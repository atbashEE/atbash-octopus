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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the current Subject to be a &quot;guest&quot;, that is, they are not authenticated <em>or</em> remembered
 * from a previous session for the annotated class/instance/method to be accessed or invoked.
 * <p/>
 * This annotation is the logical inverse of the {@link RequiresUser RequiresUser} annotation. That is,
 * <code>RequiresUser == !RequiresGuest</code>, or more accurately,
 * <p/>
 * <code>RequiresGuest === subject.{@link org.apache.shiro.subject.Subject#getPrincipal() getPrincipal()} == null</code>.
 *
 * @see RequiresAuthentication
 * @see RequiresUser
 */
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@ShiroEquivalent(shiroClassNames = "org.apache.shiro.authz.annotation.RequiresGuest")
public @interface RequiresGuest {
}
