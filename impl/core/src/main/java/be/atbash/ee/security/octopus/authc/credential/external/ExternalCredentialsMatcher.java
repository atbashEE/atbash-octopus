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
package be.atbash.ee.security.octopus.authc.credential.external;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.util.PublicAPI;

@PublicAPI
public interface ExternalCredentialsMatcher {

    /**
     * Initialization of the external matcher.
     */
    void init();

    /**
     * Returns {@code true} if the provided token credentials match the stored account credentials,
     * {@code false} otherwise.
     *
     * @param info  the {@code AuthenticationInfo} stored in the system.
     * @param credentials  the password entered by the user.
     * @return {@code true} if the provided token credentials match the stored account credentials,
     * {@code false} otherwise.
     */
    boolean areCredentialsValid(AuthenticationInfo info, char[] credentials);

}