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


import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.util.StringUtils;

import java.io.Serializable;
import java.security.SecureRandom;


/**
 * The base class for representing identifiers and identities. Provides
 * constructors that generate Base64URL-encoded secure random identifier
 * values.
 *
 * <p>Extending classes must override the {@link #equals} method.
 */
public class Identifier implements Serializable, Comparable<Identifier> {


    /**
     * The default byte length of generated identifiers.
     */
    public static final int DEFAULT_BYTE_LENGTH = 32;


    /**
     * The secure random generator.
     */
    protected static final SecureRandom secureRandom = new SecureRandom();


    /**
     * The identifier value.
     */
    private final String value;


    /**
     * Creates a new identifier with the specified value.
     *
     * @param value The identifier value. Must not be {@code null} or empty
     *              string.
     */
    public Identifier(String value) {

        if (StringUtils.isEmpty(value)) {
            throw new IllegalArgumentException("The value must not be null or empty string");
        }

        this.value = value;
    }


    /**
     * Creates a new identifier with a randomly generated value of the
     * specified byte length, Base64URL-encoded.
     *
     * @param byteLength The byte length of the value to generate. Must be
     *                   greater than one.
     */
    public Identifier(int byteLength) {

        if (byteLength < 1) {
            throw new IllegalArgumentException("The byte length must be a positive integer");
        }

        byte[] n = new byte[byteLength];

        secureRandom.nextBytes(n);

        value = Base64URLValue.encode(n).toString();
    }


    /**
     * Creates a new identifier with a randomly generated 256-bit
     * (32-byte) value, Base64URL-encoded.
     */
    public Identifier() {

        this(DEFAULT_BYTE_LENGTH);
    }


    /**
     * Returns the value of this identifier.
     *
     * @return The value.
     */
    public String getValue() {

        return value;
    }


    /**
     * Returns the JSON string representation of this identifier.
     *
     * @return The JSON string.
     */

    public String toJSONString() {

        return "\"" + value + '"';
    }


    /**
     * @see #getValue
     */
    @Override
    public String toString() {

        return getValue();
    }


    @Override
    public int compareTo(Identifier other) {

        return getValue().compareTo(other.getValue());
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        Identifier that = (Identifier) o;

        return getValue() != null ? getValue().equals(that.getValue()) : that.getValue() == null;

    }


    @Override
    public int hashCode() {
        return getValue() != null ? getValue().hashCode() : 0;
    }
}