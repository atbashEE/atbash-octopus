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
package be.atbash.ee.security.octopus.token;

import be.atbash.ee.security.octopus.ShiroEquivalent;

/**
 * An {@code AuthenticationToken} that indicates if the user wishes their identity to be remembered across sessions.
 * <p/>
 * Note however that when a new session is created for the corresponding user, that user's identity would be
 * remembered, but they are <em>NOT</em> considered authenticated.  Please see the
 * {@link org.apache.shiro.subject.Subject#isRemembered()} JavaDoc for an in-depth explanation of the semantic
 * differences of what it means to be remembered vs. authenticated.
 *
 * @see org.apache.shiro.subject.Subject#isRemembered()
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authc.RememberMeAuthenticationToken"})
public interface RememberMeAuthenticationToken extends AuthenticationToken {

    /**
     * Returns {@code true} if the submitting user wishes their identity (principal(s)) to be remembered
     * across sessions, {@code false} otherwise.
     *
     * @return {@code true} if the submitting user wishes their identity (principal(s)) to be remembered
     * across sessions, {@code false} otherwise.
     */
    boolean isRememberMe();

}