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
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class HashBasedPairwiseSubjectCodecTest {

    @Test
    public void testAlgConstant() {
        assertThat(HashBasedPairwiseSubjectCodec.HASH_ALGORITHM).isEqualTo("SHA-256");
    }

    @Test
    public void testEncode() {

        // Generate salt
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);
        assertThat(codec.getSalt()).isEqualTo(salt);
        assertThat(codec.getProvider()).isNull();

        SectorID sectorID = new SectorID("example.com");
        Subject localSubject = new Subject("alice");

        Subject pairwiseSubject = codec.encode(sectorID, localSubject);
        System.out.println("Pairwise subject: " + pairwiseSubject);
        assertThat(new Base64URLValue(pairwiseSubject.getValue()).decode().length * 8).isEqualTo(256);
    }

    @Test
    public void testConstructorConsistency() {

        // Generate salt
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);
        assertThat(codec.getSalt()).isEqualTo(salt);
        assertThat(codec.getProvider()).isNull();

        SectorID sectorID = new SectorID("example.com");
        Subject localSubject = new Subject("alice");

        Subject s1 = codec.encode(sectorID, localSubject);

        codec = new HashBasedPairwiseSubjectCodec(Base64URLValue.encode(salt));
        Subject s2 = codec.encode(sectorID, localSubject);

        assertThat(s2).isEqualTo(s1);
    }

    @Test
    public void testEncodeWithProvider() {

        // Generate salt
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);
        assertThat(codec.getSalt()).isEqualTo(salt);
        assertThat(codec.getProvider()).isNull();

        codec.setProvider(BouncyCastleProviderSingleton.getInstance());
        assertThat(codec.getProvider()).isEqualTo(BouncyCastleProviderSingleton.getInstance());

        SectorID sectorID = new SectorID("example.com");
        Subject localSubject = new Subject("alice");

        Subject pairwiseSubject = codec.encode(sectorID, localSubject);
        System.out.println("Pairwise subject: " + pairwiseSubject);
        assertThat(new Base64URLValue(pairwiseSubject.getValue()).decode().length * 8).isEqualTo(256);
    }

    @Test
    public void testDecode() {

        // Generate salt
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);

        try {
            codec.decode(new Subject("xyz"));
            fail();
        } catch (UnsupportedOperationException e) {
            assertThat(e.getMessage()).isEqualTo("Pairwise subject decoding is not supported");
        }
    }
}
