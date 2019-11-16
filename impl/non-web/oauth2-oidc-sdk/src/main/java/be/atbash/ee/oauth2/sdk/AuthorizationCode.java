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


import be.atbash.ee.oauth2.sdk.id.Identifier;

/**
 * Authorisation code. A maximum authorization code lifetime of 10 minutes is
 * recommended.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 1.3.1.
 * </ul>
 */
public final class AuthorizationCode extends Identifier {


    /**
     * Creates a new authorisation code with the specified value.
     *
     * @param value The code value. Must not be {@code null} or empty
     *              string.
     */
    public AuthorizationCode(final String value) {

        super(value);
    }


    /**
     * Creates a new authorisation code with a randomly generated value of
     * the specified byte length, Base64URL-encoded.
     *
     * @param byteLength The byte length of the value to generate. Must be
     *                   greater than one.
     */
    public AuthorizationCode(final int byteLength) {

        super(byteLength);
    }


    /**
     * Creates a new authorisation code with a randomly generated 256-bit
     * (32-byte) value, Base64URL-encoded.
     */
    public AuthorizationCode() {

        super();
    }


    @Override
    public boolean equals(final Object object) {

        return object instanceof AuthorizationCode &&
                this.toString().equals(object.toString());
    }
}
