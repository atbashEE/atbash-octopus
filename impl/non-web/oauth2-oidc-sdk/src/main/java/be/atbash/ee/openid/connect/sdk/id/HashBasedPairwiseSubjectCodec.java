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
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * SHA-256 based encoder of pairwise subject identifiers. Reversal is not
 * supported.
 *
 * <p>Algorithm:
 *
 * <pre>
 * sub = SHA-256 ( sector_id || local_sub || salt )
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 8.1.
 * </ul>
 */
// FIXME Will this be used in Octopus?
public class HashBasedPairwiseSubjectCodec extends PairwiseSubjectCodec {


    /**
     * The hashing algorithm.
     */
    public static final String HASH_ALGORITHM = "SHA-256";


    /**
     * Creates a new hash-based codec for pairwise subject identifiers.
     *
     * @param salt The salt, must not be {@code null}.
     */
    public HashBasedPairwiseSubjectCodec(byte[] salt) {
        super(salt);
        if (salt == null) {
            throw new IllegalArgumentException("The salt must not be null");
        }
    }


    /**
     * Creates a new hash-based codec for pairwise subject identifiers.
     *
     * @param salt The salt, must not be {@code null}.
     */
    public HashBasedPairwiseSubjectCodec(Base64URLValue salt) {
        super(salt.decode());
    }


    @Override
    public Subject encode(SectorID sectorID, Subject localSub) {

        MessageDigest sha256;
        try {
            if (getProvider() != null) {
                sha256 = MessageDigest.getInstance(HASH_ALGORITHM, getProvider());
            } else {
                sha256 = MessageDigest.getInstance(HASH_ALGORITHM);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        sha256.update(sectorID.getValue().getBytes(CHARSET));
        sha256.update(localSub.getValue().getBytes(CHARSET));
        byte[] hash = sha256.digest(getSalt());

        return new Subject(Base64URLValue.encode(hash).toString());
    }
}
