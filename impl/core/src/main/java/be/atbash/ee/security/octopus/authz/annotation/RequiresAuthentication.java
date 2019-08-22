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
package be.atbash.ee.security.octopus.authz.annotation;

import be.atbash.ee.security.octopus.ShiroEquivalent;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the current Subject to have been authenticated <em>during their current session</em> for the annotated
 * class/instance/method to be accessed or invoked.  This is <em>more</em> restrictive than the
 * {@link RequiresUser RequiresUser} annotation.
 * <p/>
 * This annotation basically ensures that
 * <code>{@link be.atbash.ee.security.octopus.subject.Subject subject}.{@link be.atbash.ee.security.octopus.subject.Subject#isAuthenticated() isAuthenticated()} === true</code>
 * <p/>
 * See the {@link RequiresUser RequiresUser} and
 * {@link be.atbash.ee.security.octopus.token.RememberMeAuthenticationToken RememberMeAuthenticationToken} JavaDoc for an
 * explaination of why these two states are considered different.
 *
 * @see RequiresUser
 * @see RequiresGuest
 */
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@ShiroEquivalent(shiroClassNames = "org.apache.shiro.authz.annotation.RequiresAuthentication")
public @interface RequiresAuthentication {
}
