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
package be.atbash.ee.security.octopus.util.reflection;

import be.atbash.ee.security.octopus.OctopusException;
import be.atbash.ee.security.octopus.ShiroEquivalent;

/**
 * Runtime exception thrown by the framework when unable to instantiate a Class via reflection.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.util.InstantiationException"})
public class InstantiationException extends OctopusException {

    /**
     * Creates a new InstantiationException.
     */
    public InstantiationException() {
        super();
    }

    /**
     * Constructs a new InstantiationException.
     *
     * @param message the reason for the exception
     */
    public InstantiationException(String message) {
        super(message);
    }

    /**
     * Constructs a new InstantiationException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public InstantiationException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InstantiationException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public InstantiationException(String message, Throwable cause) {
        super(message, cause);
    }
}
