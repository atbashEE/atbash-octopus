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
package be.atbash.ee.oauth2.sdk.id;


import be.atbash.util.StringUtils;

/**
 * Opaque value used to maintain state between a request and a callback. Also
 * serves as a protection against XSRF attacks, among other uses.
 */
public final class State extends Identifier {


    /**
     * Creates a new state with the specified value.
     *
     * @param value The state value. Must not be {@code null} or empty
     *              string.
     */
    public State(final String value) {

        super(value);
    }


    /**
     * Creates a new state with a randomly generated value of the specified
     * byte length, Base64URL-encoded.
     *
     * @param byteLength The byte length of the value to generate. Must be
     *                   greater than one.
     */
    public State(final int byteLength) {

        super(byteLength);
    }


    /**
     * Creates a new state with a randomly generated 256-bit (32-byte)
     * value, Base64URL-encoded.
     */
    public State() {

        super();
    }


    @Override
    public boolean equals(final Object object) {

        return object instanceof State &&
                this.toString().equals(object.toString());
    }


    /**
     * Parses a state from the specified string.
     *
     * @param data The string to parse, {@code null} or empty if no state is
     *             specified.
     * @return The state, {@code null} if the parsed string was
     * {@code null} or empty.
     */
    public static State parse(final String data) {

        if (StringUtils.isEmpty(data)) {

            return null;
        }
        return new State(data);
    }
}
