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
package be.atbash.ee.security.octopus.authc;

import be.atbash.ee.security.octopus.ShiroEquivalent;

/**
 * Exception thrown due to a problem with the account
 * under which an authentication attempt is being executed.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authc.AccountException"})
class AccountException extends AuthenticationException {

    /**
     * Creates a new AccountException.
     */
    AccountException() {
        super();
    }

    /**
     * Constructs a new AccountException.
     *
     * @param message the reason for the exception
     */
    AccountException(String message) {
        super(message);
    }

    /**
     * Constructs a new AccountException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    AccountException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new AccountException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    AccountException(String message, Throwable cause) {
        super(message, cause);
    }

}
