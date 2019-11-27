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
package be.atbash.ee.openid.connect.sdk.id;


import be.atbash.ee.oauth2.sdk.id.Subject;

import java.net.URI;
import java.nio.charset.Charset;
import java.security.Provider;
import java.util.Map;


/**
 * Encoder and decoder of pairwise subject identifiers. The encoder algorithms
 * must be deterministic, to ensure a given set of inputs always produces an
 * identical pairwise subject identifier.
 *
 * <p>Decoding pairwise subject identifiers is optional, and is implemented by
 * algorithms that supported reversal (typically with encryption-based codecs).
 * Hash-based codecs don't support reversal.
 *
 * <p>Codec implementations thread-safe.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 8.1.
 * </ul>
 */
public abstract class PairwiseSubjectCodec {


    /**
     * The charset (UTF-8) for string to byte conversions.
     */
    public static final Charset CHARSET = Charset.forName("UTF-8");


    /**
     * The salt.
     */
    private final byte[] salt;


    /**
     * The security provider.
     */
    private Provider provider;


    /**
     * Creates a new codec for pairwise subject identifiers.
     *
     * @param salt The salt, {@code null} if not required.
     */
    public PairwiseSubjectCodec(byte[] salt) {

        this.salt = salt;
    }


    /**
     * Returns the salt.
     *
     * @return The salt, {@code null} if not required.
     */
    public byte[] getSalt() {
        return salt;
    }


    /**
     * Gets the security provider for cryptographic operations.
     *
     * @return The security provider, {@code null} if not specified
     * (implies the default one).
     */
    public Provider getProvider() {
        return provider;
    }


    /**
     * Sets the security provider for cryptographic operations.
     *
     * @param provider The security provider, {@code null} if not specified
     *                 (implies the default one).
     */
    public void setProvider(Provider provider) {
        this.provider = provider;
    }


    /**
     * Encodes a new pairwise subject identifier from the specified sector
     * identifier URI and local subject.
     *
     * @param sectorURI The sector identifier URI. Its scheme should be
     *                  "https", must include a host portion and must not
     *                  be {@code null}.
     * @param localSub  The local subject identifier. Must not be
     *                  {@code null}.
     * @return The pairwise subject identifier.
     */
    public Subject encode(URI sectorURI, Subject localSub) {

        return encode(new SectorID(sectorURI), localSub);
    }


    /**
     * Encodes a new pairwise subject identifier from the specified sector
     * identifier and local subject.
     *
     * @param sectorID The sector identifier. Must not be
     *                 {@code null}.
     * @param localSub The local subject identifier. Must not be
     *                 {@code null}.
     * @return The pairwise subject identifier.
     */
    public abstract Subject encode(SectorID sectorID, Subject localSub);


    /**
     * Decodes the specified pairwise subject identifier to produce the
     * matching sector identifier and local subject. Throws a
     * {@link UnsupportedOperationException}. Codecs that support pairwise
     * subject identifier reversal should override this method.
     *
     * @param pairwiseSubject The pairwise subject identifier. Must be
     *                        valid and not {@code null}.
     * @return The matching sector identifier and local subject.
     */
    public Map.Entry<SectorID, Subject> decode(Subject pairwiseSubject)
             {

        throw new UnsupportedOperationException("Pairwise subject decoding is not supported");
    }
}
