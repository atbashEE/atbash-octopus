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
package be.atbash.ee.oauth2.sdk.pkce;


import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

/**
 * Authorisation code verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636).
 * </ul>
 */
public class CodeVerifier extends Secret {


    /**
     * The minimum character length of a code verifier.
     */
    public static final int MIN_LENGTH = 43;

    /**
     * The minimum character length of a code verifier.
     */
    public static final int RAW_MIN_LENGTH = 32;


    /**
     * The maximum character length of a code verifier.
     */
    public static final int MAX_LENGTH = 128;


    /**
     * Creates a new code verifier with the specified value.
     *
     * @param value The code verifier value. Must not contain characters
     *              other than [A-Z] / [a-z] / [0-9] / "-" / "." / "_" /
     *              "~". The verifier length must be at least 43
     *              characters but not more than 128 characters. Must not
     *              be {@code null} or empty string.
     */
    public CodeVerifier(String value) {
        super(value);

        if (value.length() < MIN_LENGTH) {
            throw new IllegalArgumentException("The code verifier must be at least " + MIN_LENGTH + " characters");
        }

        if (value.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("The code verifier must not be longer than " + MAX_LENGTH + " characters");
        }
    }

    /**
     * Creates a new code verifier with the specified value.
     *
     * @param value The code verifier value. Must not contain characters
     *              other than [A-Z] / [a-z] / [0-9] / "-" / "." / "_" /
     *              "~". The verifier length must be at least 43
     *              characters but not more than 128 characters. Must not
     *              be {@code null} or empty string.
     */
    public CodeVerifier( Base64URLValue value) {
        super(value);

        if (this.value.length < RAW_MIN_LENGTH) {
            throw new IllegalArgumentException("The code verifier must be at least " + MIN_LENGTH + " characters");
        }

        if (this.value.length > MAX_LENGTH) {
            throw new IllegalArgumentException("The code verifier must not be longer than " + MAX_LENGTH + " characters");
        }
    }


    /**
     * Generates a new code verifier represented by a secure random 256-bit
     * number that is Base64URL-encoded (as a 43 character string, which is
     * the {@link #MIN_LENGTH minimum character length} of a code
     * verifier).
     */
    public CodeVerifier() {
        super(32);
    }


    @Override
    public boolean equals(Object object) {
        return object instanceof CodeVerifier && super.equals(object);
    }
}
