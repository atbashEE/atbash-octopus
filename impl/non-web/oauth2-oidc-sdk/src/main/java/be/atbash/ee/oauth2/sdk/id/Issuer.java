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


import java.net.URI;
import java.net.URISyntaxException;


/**
 * Issuer identifier.
 *
 * <p>Valid issuer identifiers are URIs with "https" schema and no query or
 * fragment component.
 */
public final class Issuer extends Identifier {


    /**
     * Checks if the specified string represents a valid issuer identifier.
     * This method is {@code null}-safe.
     *
     * @param value The issuer string.
     * @return {@code true} if the string represents a valid issuer
     * identifier, else {@code false}.
     */
    public static boolean isValid(String value) {

        if (value == null) {
            return false;
        }

        try {
            return isValid(new URI(value));

        } catch (URISyntaxException e) {

            return false;
        }
    }


    /**
     * Checks if the specified issuer is a valid identifier. This method is
     * {@code null}-safe.
     *
     * @param value The issuer.
     * @return {@code true} if the value is a valid identifier, else
     * {@code false}.
     */
    public static boolean isValid(Issuer value) {

        if (value == null) {
            return false;
        }

        try {
            return isValid(new URI(value.getValue()));

        } catch (URISyntaxException e) {

            return false;
        }
    }


    /**
     * Checks if the specified URI represents a valid issuer identifier.
     * This method is {@code null}-safe.
     *
     * @param value The URI.
     * @return {@code true} if the values represents a valid issuer
     * identifier, else {@code false}.
     */
    public static boolean isValid(URI value) {

        if (value == null) {
            return false;
        }

        if (value.getScheme() == null || !value.getScheme().equalsIgnoreCase("https")) {
            return false;
        }

        if (value.getRawQuery() != null) {
            return false;
        }

        return value.getRawFragment() == null;

    }


    /**
     * Creates a new issuer identifier with the specified value.
     *
     * @param value The issuer identifier value. Must not be {@code null}
     *              or empty string.
     */
    public Issuer(String value) {

        super(value);
    }


    /**
     * Creates a new issuer identifier with the specified URI value.
     *
     * @param value The URI value. Must not be {@code null}.
     */
    public Issuer(URI value) {

        super(value.toString());
    }


    /**
     * Creates a new issuer identifier with the specified value.
     *
     * @param value The value. Must not be {@code null}.
     */
    public Issuer(Identifier value) {

        super(value.getValue());
    }


    /**
     * Checks if this issuer is a valid identifier. This method is
     * {@code null}-safe.
     *
     * @return {@code true} if the value is a valid identifier, else
     * {@code false}.
     */
    public boolean isValid() {

        return Issuer.isValid(this);
    }


    @Override
    public boolean equals(Object object) {

        return object instanceof Issuer && this.toString().equals(object.toString());
    }
}