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
package be.atbash.ee.security.octopus.cache;

import be.atbash.ee.security.octopus.OctopusException;
import be.atbash.ee.security.octopus.ShiroEquivalent;

/**
 * Root class of all Shiro exceptions related to caching operations.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.cache.CacheException"})
public class CacheException extends OctopusException {

    /**
     * Creates a new <code>CacheException</code>.
     */
    public CacheException() {
        super();
    }

    /**
     * Creates a new <code>CacheException</code>.
     *
     * @param message the reason for the exception.
     */
    public CacheException(String message) {
        super(message);
    }

    /**
     * Creates a new <code>CacheException</code>.
     *
     * @param cause the underlying cause of the exception.
     */
    public CacheException(Throwable cause) {
        super(cause);
    }

    /**
     * Creates a new <code>CacheException</code>.
     *
     * @param message the reason for the exception.
     * @param cause   the underlying cause of the exception.
     */
    public CacheException(String message, Throwable cause) {
        super(message, cause);
    }
}
