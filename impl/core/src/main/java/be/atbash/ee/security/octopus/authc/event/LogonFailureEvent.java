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
package be.atbash.ee.security.octopus.authc.event;

import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.util.PublicAPI;

@PublicAPI
public class LogonFailureEvent {
    private AuthenticationToken authenticationToken;
    protected AuthenticationException authenticationException;

    public LogonFailureEvent(AuthenticationToken authenticationToken, AuthenticationException authenticationException) {
        this.authenticationToken = authenticationToken;
        this.authenticationException = authenticationException;
    }

    public AuthenticationToken getAuthenticationToken() {
        return authenticationToken;
    }

    public AuthenticationException getException() {
        return authenticationException;
    }
}
