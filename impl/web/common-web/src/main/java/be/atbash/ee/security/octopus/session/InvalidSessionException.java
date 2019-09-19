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
package be.atbash.ee.security.octopus.session;

import be.atbash.ee.security.octopus.ShiroEquivalent;

/**
 * Exception thrown when attempting to interact with the system under an established session
 * when that session is considered invalid.  The meaning of the term 'invalid' is based on
 * application behavior.  For example, a Session is considered invalid if it has been explicitly
 * stopped (e.g. when a user logs-out or when explicitly
 * {@link Session#stop() stopped} programmatically.  A Session can also be
 * considered invalid if it has expired.
 *
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.session.InvalidSessionException"})
public class InvalidSessionException extends SessionException {

    /**
     * Constructs a new InvalidSessionException.
     *
     * @param message the reason for the exception
     */
    public InvalidSessionException(String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidSessionException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public InvalidSessionException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidSessionException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public InvalidSessionException(String message, Throwable cause) {
        super(message, cause);
    }

}
