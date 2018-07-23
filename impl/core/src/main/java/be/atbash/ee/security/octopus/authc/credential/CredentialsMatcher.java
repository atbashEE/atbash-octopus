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
package be.atbash.ee.security.octopus.authc.credential;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.token.AuthenticationToken;

/**
 * Interface implemented by classes that can determine if an AuthenticationToken's provided
 * credentials matches a corresponding account's credentials stored in the system.
 *
 * <p>Simple direct comparisons are handled well by the
 * {@link DefaultCredentialsMatcher DefaultCredentialsMatcher} which also supports the scenario with hashed passwords.
 *
 * @see DefaultCredentialsMatcher
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authc.credential.CredentialsMatcher"})
public interface CredentialsMatcher {

    /**
     * Returns {@code true} if the provided token credentials match the stored account credentials,
     * {@code false} otherwise.
     *
     * @param token the {@code AuthenticationToken} submitted during the authentication attempt
     * @param info  the {@code AuthenticationInfo} stored in the system.
     * @return {@code true} if the provided token credentials match the stored account credentials,
     * {@code false} otherwise.
     */
    boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info);

}