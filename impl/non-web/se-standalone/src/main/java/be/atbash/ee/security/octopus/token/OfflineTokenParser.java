/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.token;

import be.atbash.ee.security.octopus.jwt.decoder.JWTData;
import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.decoder.JWTVerifier;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SingleKeySelector;
import be.atbash.ee.security.octopus.nimbus.jwt.CommonJWTHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static be.atbash.ee.security.octopus.token.OfflineToken.LOCAL_SECRET_KEY_ID;

/**
 *
 */

public final class OfflineTokenParser {

    private OfflineTokenParser() {
    }

    public static OfflineToken parse(String token, String passPhrase) {
        byte[] localSecret = LocalSecretFactory.generateSecret(passPhrase);

        JWTDecoder decode = new JWTDecoder();

        SecretKey key = new SecretKeySpec(localSecret, 0, localSecret.length, "AES");

        AtbashKey atbashKey = new AtbashKey(LOCAL_SECRET_KEY_ID, key);
        KeySelector selector = new SingleKeySelector(atbashKey);
        JWTData<OfflineToken> jwtData = decode.decode(token, OfflineToken.class, selector, new OfflineTokenVerifier());
        return jwtData.getData();

    }

    private static class OfflineTokenVerifier implements JWTVerifier {

        @Override
        public boolean verify(CommonJWTHeader header, JWTClaimsSet jwtClaimsSet) {
            return header.getCustomParameters().containsKey("Octopus Offline");  // Fixme Constant
        }
    }
}
