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


import be.atbash.ee.oauth2.sdk.id.Identifier;

/**
 * Method that was used to derive an authorisation code challenge.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636).
 * </ul>
 */
public final class CodeChallengeMethod extends Identifier {


    /**
     * Plain code challenge method.
     */
    public static final CodeChallengeMethod PLAIN = new CodeChallengeMethod("plain");


    /**
     * SHA-256 code challenge method.
     */
    public static final CodeChallengeMethod S256 = new CodeChallengeMethod("S256");


    /**
     * Gets the default code challenge method.
     *
     * @return {@link #PLAIN}
     */
    public static CodeChallengeMethod getDefault() {

        return PLAIN;
    }


    /**
     * @param value The code challenge method value. Must not be
     *              {@code null} or empty string.
     */
    public CodeChallengeMethod(final String value) {

        super(value);
    }


    /**
     * Parses a code challenge method from the specified value.
     *
     * @param value The code challenge method value. Must not be
     *              {@code null} or empty string.
     * @return The code challenge method.
     */
    public static CodeChallengeMethod parse(final String value) {

        if (value.equals(PLAIN.getValue())) {
            return PLAIN;
        } else if (value.equals(S256.getValue())) {
            return S256;
        } else {
            return new CodeChallengeMethod(value);
        }
    }


    @Override
    public boolean equals(final Object object) {

        return object instanceof CodeChallengeMethod &&
                this.toString().equals(object.toString());
    }
}
