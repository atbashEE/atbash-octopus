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
package be.atbash.ee.oauth2.sdk.auth;


import be.atbash.ee.security.octopus.nimbus.jose.crypto.utils.ConstantTimeUtils;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;


/**
 * Secret. The secret value should be {@link #erase erased} when no longer in
 * use.
 */
public class Secret {


    /**
     * The default byte length of generated secrets.
     */
    public static final int DEFAULT_BYTE_LENGTH = 32;


    /**
     * The secure random generator.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();


    /**
     * The secret value.
     */
    protected byte[] value;

    private boolean fromBase64Value;

    /**
     * Optional expiration date.
     */
    private final Date expDate;


    /**
     * Creates a new secret with the specified value.
     *
     * @param value The secret value. May be an empty string. Must be
     *              UTF-8 encoded and not {@code null}.
     */
    public Secret(String value) {
        // Also a 'plain' secret is allowed meaning a human readable password for some scenarios
        this(value, null);
    }


    /**
     * Creates a new secret with the specified value and expiration date.
     *
     * @param value   The secret value. May be an empty string. Must be
     *                UTF-8 encoded and not {@code null}.
     * @param expDate The expiration date, {@code null} if not specified.
     */
    public Secret(String value, Date expDate) {

        this.value = value.getBytes(StandardCharsets.UTF_8);
        this.expDate = expDate;
    }

    /**
     * Creates a new secret with the specified value.
     *
     * @param value The secret value. May be an empty string. Must be
     *              UTF-8 encoded and not {@code null}.
     */
    public Secret(Base64URLValue value) {

        this(value, null);
    }


    /**
     * Creates a new secret with the specified value and expiration date.
     *
     * @param value   The secret value. May be an empty string. Must be
     *                UTF-8 encoded and not {@code null}.
     * @param expDate The expiration date, {@code null} if not specified.
     */
    public Secret(Base64URLValue value, Date expDate) {

        this.value = value.decode();
        this.expDate = expDate;
        fromBase64Value = true;
    }

    /**
     * Generates a new secret with a cryptographic random value of the
     * specified byte length, Base64URL-encoded.
     *
     * @param byteLength The byte length of the secret value to generate.
     *                   Must be greater than one.
     */
    public Secret(int byteLength) {

        this(byteLength, null);
    }


    /**
     * Generates a new secret with a cryptographic random value of the
     * specified byte length, Base64URL-encoded, and the specified
     * expiration date.
     *
     * @param byteLength The byte length of the secret value to generate.
     *                   Must be greater than one.
     * @param expDate    The expiration date, {@code null} if not
     *                   specified.
     */
    public Secret(int byteLength, Date expDate) {

        if (byteLength < 1) {
            throw new IllegalArgumentException("The byte length must be a positive integer");
        }

        byte[] n = new byte[byteLength];

        SECURE_RANDOM.nextBytes(n);

        value = n;
        fromBase64Value = true; // Well actually just a bunch of random bytes so nothing human readable.

        this.expDate = expDate;
    }


    /**
     * Generates a new secret with a cryptographic 256-bit (32-byte) random
     * value, Base64URL-encoded.
     */
    public Secret() {

        this(DEFAULT_BYTE_LENGTH);
    }


    /**
     * Gets the value of this secret.
     *
     * @return The value as a UTF-8 encoded string, {@code null} if it has
     * been erased.
     */
    public String getValue() {

        if (value == null) {
            return null; // value has been erased
        }

        if (fromBase64Value) {
            return Base64URLValue.encode(value).toString();
        } else {
            return new String(value, StandardCharsets.UTF_8);
        }
    }


    /**
     * Gets the value of this secret.
     *
     * @return The value as a byte array, {@code null} if it has
     * been erased.
     */
    public byte[] getValueBytes() {

        return value;
    }


    /**
     * Gets the SHA-256 hash of this secret.
     *
     * @return The SHA-256 hash, {@code null} if the secret value has been
     * erased.
     */
    public byte[] getSHA256() {

        if (value == null) {
            return null;
        }

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(value);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * Erases of the value of this secret.
     */
    public void erase() {

        if (value == null) {
            return; // Already erased
        }

        for (int i = 0; i < value.length; i++) {
            value[i] = 0;
        }

        value = null;
    }


    /**
     * Gets the expiration date of this secret.
     *
     * @return The expiration date, {@code null} if not specified.
     */
    public Date getExpirationDate() {

        return expDate;
    }


    /**
     * Checks is this secret has expired.
     *
     * @return {@code true} if the secret has an associated expiration date
     * which is in the past (according to the current system time),
     * else returns {@code false}.
     */
    public boolean expired() {

        if (expDate == null) {
            return false; // never expires
        }

        final Date now = new Date();

        return expDate.before(now);
    }


    /**
     * Constant time comparison of the SHA-256 hashes of this and another
     * secret.
     *
     * @param other The other secret. May be {@code null}.
     * @return {@code true} if the SHA-256 hashes of the two secrets are
     * equal, else {@code false}.
     */
    public boolean equalsSHA256Based(Secret other) {

        if (other == null) {
            return false;
        }

        byte[] thisHash = getSHA256();
        byte[] otherHash = other.getSHA256();

        if (thisHash == null || otherHash == null) {
            return false;
        }

        return ConstantTimeUtils.areEqual(thisHash, otherHash);
    }


    /**
     * Comparison with another secret is constant time.
     *
     * @param o The other object. May be {@code null}.
     * @return {@code true} if both objects are equal, else {@code false}.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (value == null) {
            return false;
        }
        if (!(o instanceof Secret)) {
            return false;
        }
        Secret secret = (Secret) o;
        return ConstantTimeUtils.areEqual(value, secret.value);
    }


    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }
}