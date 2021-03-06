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
package be.atbash.ee.security.octopus.crypto.hash;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.crypto.UnknownAlgorithmException;
import be.atbash.util.PublicAPI;
import be.atbash.util.StringUtils;
import be.atbash.util.codec.*;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

/**
 * A {@code Hash} implementation that allows any {@link MessageDigest MessageDigest} algorithm name to
 * be used. Hashes with salt are encouraged to use.
 * <p/>
 * Instances should be created by using the {@link HashFactory}.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.crypto.hash.AbstractHash", "org.apache.shiro.crypto.hash.Hash", "org.apache.shiro.crypto.hash.SimpleHash"})
@PublicAPI
public class Hash extends CodecSupport implements Serializable {

    private static final int DEFAULT_ITERATIONS = 1;

    /**
     * The {@link MessageDigest MessageDigest} algorithm name to use when performing the hash.
     */
    private final String algorithmName;

    /**
     * The hashed data
     */
    private byte[] bytes;

    /**
     * Supplied salt, if any.
     */
    private ByteSource salt;

    /**
     * Number of hash iterations to perform.  Defaults to 1 in the constructor.
     */
    private int iterations;

    /**
     * Cached value of the {@link #toHex() toHex()} call so multiple calls won't incur repeated overhead.
     */
    private transient String hexEncoded = null;

    /**
     * Cached value of the {@link #toBase64() toBase64()} call so multiple calls won't incur repeated overhead.
     */
    private transient String base64Encoded = null;

    /**
     * Creates an {@code algorithmName}-specific hash of the specified {@code source} using the given {@code salt}
     * using a single hash iteration.
     * <p/>
     * It is a convenience constructor that merely executes <code>this( algorithmName, source, salt, 1);</code>.
     * <p/>
     * Please see the
     * {@link #Hash(String algorithmName, Object source, Object salt, int numIterations) SimpleHashHash(algorithmName, Object,Object,int)}
     * constructor for the types of Objects that may be passed into this constructor, as well as how to support further
     * types.
     *
     * @param algorithmName the {@link MessageDigest MessageDigest} algorithm name to use when
     *                      performing the hash.
     * @param source        the source object to be hashed.
     * @param salt          the salt to use for the hash
     * @throws CodecException            if either constructor argument cannot be converted into a byte array.
     * @throws UnknownAlgorithmException if the {@code algorithmName} is not available.
     */
    public Hash(String algorithmName, Object source, Object salt) throws CodecException, UnknownAlgorithmException {
        this(algorithmName, source, salt, DEFAULT_ITERATIONS);
    }

    /**
     * Creates an {@code algorithmName}-specific hash of the specified {@code source} using the given
     * {@code salt} a total of {@code hashIterations} times.
     * <p/>
     * By default, this class only supports Object method arguments of
     * type {@code byte[]}, {@code char[]}, {@link String}, {@link java.io.File File},
     * {@link java.io.InputStream InputStream} or {@link ByteSource}.  If either
     * argument is anything other than these types a {@link CodecException CodecException}
     * will be thrown.
     * <p/>
     * If you want to be able to hash other object types, or use other salt types, you need to implement a custom {@link ByteSourceCreator}.
     * Your other option is to
     * convert your arguments to one of the default supported types first before passing them in to this
     * constructor}.
     *
     * @param algorithmName  the {@link MessageDigest MessageDigest} algorithm name to use when
     *                       performing the hash.
     * @param source         the source object to be hashed.
     * @param salt           the salt to use for the hash
     * @param hashIterations the number of times the {@code source} argument hashed for attack resiliency.
     * @throws CodecException            if either Object constructor argument cannot be converted into a byte array.
     * @throws UnknownAlgorithmException if the {@code algorithmName} is not available.
     */
    public Hash(String algorithmName, Object source, Object salt, int hashIterations)
            throws CodecException, UnknownAlgorithmException {
        if (!StringUtils.hasText(algorithmName)) {
            throw new NullPointerException("algorithmName argument cannot be null or empty.");
        }
        this.algorithmName = algorithmName;
        iterations = Math.max(DEFAULT_ITERATIONS, hashIterations);
        ByteSource saltBytes = null;
        if (salt != null) {
            saltBytes = convertSaltToBytes(salt);
            this.salt = saltBytes;
        }
        ByteSource sourceBytes = convertSourceToBytes(source);
        hash(sourceBytes, saltBytes, hashIterations);
    }

    /**
     * Acquires the specified {@code source} argument's bytes and returns them in the form of a {@code ByteSource} instance.
     * <p/>
     * This implementation merely delegates to the convenience {@link ByteSourceCreator.bytes((Object)} method for generic
     * conversion.  Can be overridden by subclasses for source-specific conversion.
     *
     * @param source the source object to be hashed.
     * @return the source's bytes in the form of a {@code ByteSource} instance.
     */
    private ByteSource convertSourceToBytes(Object source) {
        return ByteSource.creator.bytes(source);
    }

    /**
     * Acquires the specified {@code salt} argument's bytes and returns them in the form of a {@code ByteSource} instance.
     * <p/>
     * This implementation merely delegates to the convenience {@link ByteSourceCreator.bytes(Object)} method for generic
     * conversion.
     *
     * @param salt the salt to be use for the hash.
     * @return the salt's bytes in the form of a {@code ByteSource} instance.
     */
    private ByteSource convertSaltToBytes(Object salt) {
        return ByteSource.creator.bytes(salt);
    }

    private void hash(ByteSource source, ByteSource salt, int hashIterations) throws CodecException, UnknownAlgorithmException {
        byte[] saltBytes = salt != null ? salt.getBytes() : null;
        byte[] hashedBytes = hash(source.getBytes(), saltBytes, hashIterations);
        setBytes(hashedBytes);
    }

    /**
     * Returns the {@link MessageDigest MessageDigest} algorithm name to use when performing the hash.
     *
     * @return the {@link MessageDigest MessageDigest} algorithm name to use when performing the hash.
     */
    public String getAlgorithmName() {
        return algorithmName;
    }

    public ByteSource getSalt() {
        return salt;
    }

    public int getIterations() {
        return iterations;
    }

    public byte[] getBytes() {
        return bytes;
    }

    /**
     * Sets the raw bytes stored by this hash instance.
     * <p/>
     * The bytes are kept in raw form - they will not be hashed/changed.  This is primarily a utility method for
     * constructing a Hash instance when the hashed value is already known.
     *
     * @param alreadyHashedBytes the raw already-hashed bytes to store in this instance.
     */
    public void setBytes(byte[] alreadyHashedBytes) {
        bytes = alreadyHashedBytes;
        hexEncoded = null;
        base64Encoded = null;
    }

    /**
     * Sets the salt used to previously compute AN ALREADY GENERATED HASH.
     * <p/>
     * This is provided <em>ONLY</em> to reconstitute a Hash instance that has already been computed.  It should ONLY
     * ever be invoked when re-constructing a hash instance from an already-hashed value.
     *
     * @param salt the salt used to previously create the hash/digest.
     */
    public void setSalt(ByteSource salt) {
        this.salt = salt;
    }

    /**
     * Returns the JDK MessageDigest instance to use for executing the hash.
     *
     * @param algorithmName the algorithm to use for the hash, provided by subclasses.
     * @return the MessageDigest object for the specified {@code algorithm}.
     * @throws UnknownAlgorithmException if the specified algorithm name is not available.
     */
    private MessageDigest getDigest(String algorithmName) throws UnknownAlgorithmException {
        try {
            return MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException e) {
            String msg = "No native '" + algorithmName + "' MessageDigest instance available on the current JVM.";
            throw new UnknownAlgorithmException(msg, e);
        }
    }

    /**
     * Hashes the specified byte array without a salt for a single iteration.
     *
     * @param bytes the bytes to hash.
     * @return the hashed bytes.
     * @throws UnknownAlgorithmException if the configured {@link #getAlgorithmName() algorithmName} is not available.
     */
    protected byte[] hash(byte[] bytes) throws UnknownAlgorithmException {
        return hash(bytes, null, DEFAULT_ITERATIONS);
    }

    /**
     * Hashes the specified byte array using the given {@code salt} for a single iteration.
     *
     * @param bytes the bytes to hash
     * @param salt  the salt to use for the initial hash
     * @return the hashed bytes
     * @throws UnknownAlgorithmException if the configured {@link #getAlgorithmName() algorithmName} is not available.
     */
    protected byte[] hash(byte[] bytes, byte[] salt) throws UnknownAlgorithmException {
        return hash(bytes, salt, DEFAULT_ITERATIONS);
    }

    /**
     * Hashes the specified byte array using the given {@code salt} for the specified number of iterations.
     *
     * @param bytes          the bytes to hash
     * @param salt           the salt to use for the initial hash
     * @param hashIterations the number of times the the {@code bytes} will be hashed (for attack resiliency).
     * @return the hashed bytes.
     * @throws UnknownAlgorithmException if the {@link #getAlgorithmName() algorithmName} is not available.
     */
    protected byte[] hash(byte[] bytes, byte[] salt, int hashIterations) throws UnknownAlgorithmException {
        MessageDigest digest = getDigest(getAlgorithmName());
        if (salt != null) {
            digest.reset();
            digest.update(salt);
        }
        byte[] hashed = digest.digest(bytes);
        int iterations = hashIterations - DEFAULT_ITERATIONS; //already hashed once above
        //iterate remaining number:
        for (int i = 0; i < iterations; i++) {
            digest.reset();
            hashed = digest.digest(hashed);
        }
        return hashed;
    }

    public boolean isEmpty() {
        return bytes == null || bytes.length == 0;
    }

    /**
     * Returns a hex-encoded string of the underlying {@link #getBytes byte array}.
     * <p/>
     * This implementation caches the resulting hex string so multiple calls to this method remain efficient.
     * However, calling {@link #setBytes setBytes} will null the cached value, forcing it to be recalculated the
     * next time this method is called.
     *
     * @return a hex-encoded string of the underlying {@link #getBytes byte array}.
     */
    public String toHex() {
        if (hexEncoded == null) {
            hexEncoded = Hex.encodeToString(getBytes());
        }
        return hexEncoded;
    }

    /**
     * Returns a Base64-encoded string of the underlying {@link #getBytes byte array}.
     * <p/>
     * This implementation caches the resulting Base64 string so multiple calls to this method remain efficient.
     * However, calling {@link #setBytes setBytes} will null the cached value, forcing it to be recalculated the
     * next time this method is called.
     *
     * @return a Base64-encoded string of the underlying {@link #getBytes byte array}.
     */
    public String toBase64() {
        if (base64Encoded == null) {
            //cache result in case this method is called multiple times.
            base64Encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(getBytes());
        }
        return base64Encoded;
    }

    /**
     * Simple implementation that merely returns {@link #toHex() toHex()}.
     *
     * @return the {@link #toHex() toHex()} value.
     */
    public String toString() {
        return toHex();
    }

    /**
     * Returns {@code true} if the specified object is a Hash and its {@link #getBytes byte array} is identical to
     * this Hash's byte array, {@code false} otherwise.
     *
     * @param o the object (Hash) to check for equality.
     * @return {@code true} if the specified object is a Hash and its {@link #getBytes byte array} is identical to
     * this Hash's byte array, {@code false} otherwise.
     */
    public boolean equals(Object o) {
        if (o instanceof Hash) {
            Hash other = (Hash) o;
            return Arrays.equals(getBytes(), other.getBytes());
        }
        return false;
    }

    /**
     * Simply returns toHex().hashCode();
     *
     * @return toHex().hashCode()
     */
    public int hashCode() {
        if (bytes == null || bytes.length == 0) {
            return 0;
        }
        return Arrays.hashCode(bytes);
    }
}
