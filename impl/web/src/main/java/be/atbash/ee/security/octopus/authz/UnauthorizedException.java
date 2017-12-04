/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.authz;

import be.atbash.ee.security.octopus.ShiroEquivalent;

/**
 * Thrown to indicate a requested operation or access to a requested resource is not allowed.
 *
 */
// FIXME Watch out, there exists also an OctopusUnauthorizedException in first release
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authz.UnauthorizedException"})
public class UnauthorizedException extends AuthorizationException {

    /**
     * Creates a new UnauthorizedException.
     */
    public UnauthorizedException() {
        super();
    }

    /**
     * Constructs a new UnauthorizedException.
     *
     * @param message the reason for the exception
     */
    public UnauthorizedException(String message) {
        super(message);
    }

    /**
     * Constructs a new UnauthorizedException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public UnauthorizedException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new UnauthorizedException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public UnauthorizedException(String message, Throwable cause) {
        super(message, cause);
    }
}
