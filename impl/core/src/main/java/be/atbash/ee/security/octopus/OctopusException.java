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
package be.atbash.ee.security.octopus;

/**
 * Root exception for all Shiro runtime exceptions.  This class is used as the root instead
 * of {@link SecurityException} to remove the potential for conflicts;  many other
 * frameworks and products (such as J2EE containers) perform special operations when
 * encountering {@link SecurityException}.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.ShiroException"})
public class OctopusException extends RuntimeException {

    /**
     * Creates a new OctopusException.
     */
    public OctopusException() {
        super();
    }

    /**
     * Constructs a new OctopusException.
     *
     * @param message the reason for the exception
     */
    public OctopusException(String message) {
        super(message);
    }

    /**
     * Constructs a new OctopusException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public OctopusException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new OctopusException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public OctopusException(String message, Throwable cause) {
        super(message, cause);
    }

}
