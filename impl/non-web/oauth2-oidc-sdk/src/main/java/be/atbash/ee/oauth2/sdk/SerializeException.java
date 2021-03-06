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
package be.atbash.ee.oauth2.sdk;


/**
 * Serialization exception (unchecked).
 */
public class SerializeException extends RuntimeException {


    /**
     * Creates a new serialisation exception.
     *
     * @param message The exception message. May be {@code null}.
     */
    public SerializeException(String message) {

        this(message, null);
    }


    /**
     * Creates a new serialisation exception.
     *
     * @param message The exception message. May be {@code null}.
     * @param cause   The exception cause, {@code null} if not specified.
     */
    public SerializeException(String message, Throwable cause) {

        super(message, cause);
    }
}
