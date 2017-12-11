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
package be.atbash.ee.security.octopus.crypto;

import be.atbash.ee.security.octopus.ShiroEquivalent;

/**
 * Exception thrown when attempting to lookup or use a cryptographic algorithm that does not exist in the current
 * JVM environment.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.crypto.UnknownAlgorithmException"})
public class UnknownAlgorithmException extends CryptoException {

    public UnknownAlgorithmException(String message) {
        super(message);
    }

    public UnknownAlgorithmException(Throwable cause) {
        super(cause);
    }

    public UnknownAlgorithmException(String message, Throwable cause) {
        super(message, cause);
    }
}
