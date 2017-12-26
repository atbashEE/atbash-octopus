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
package be.atbash.util.exception;

/**
 * Root exception for all Atbash runtime exceptions.  This class is used as the root for all
 * Atbash eception (TODO Not all start from octopus-utils artifact !!).
 */
//@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.ShiroException"})
public class AtbashException extends RuntimeException {

    /**
     * Creates a new OctopusException.
     */

    public AtbashException() {
        super();
    }

    /**
     * Constructs a new OctopusException.
     *
     * @param message the reason for the exception
     */
    public AtbashException(String message) {
        super(message);
    }

    /**
     * Constructs a new OctopusException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public AtbashException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new OctopusException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public AtbashException(String message, Throwable cause) {
        super(message, cause);
    }

}