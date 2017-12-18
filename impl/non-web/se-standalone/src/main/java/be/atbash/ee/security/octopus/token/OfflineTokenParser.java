/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.jwt.keys.HMACSecret;
import be.atbash.ee.security.octopus.jwt.keys.KeySelector;
import be.atbash.ee.security.octopus.jwt.keys.SingleKeySelector;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;

import static be.atbash.ee.security.octopus.token.OfflineToken.LOCAL_SECRET_KEY_ID;

/**
 *
 */

public final class OfflineTokenParser {

    private OfflineTokenParser() {
    }

    public static OfflineToken parse(String token, String passPhrase) {
        String localSecret = LocalSecretFactory.generateSecret(passPhrase);

        JWTDecoder decode = new JWTDecoder();

        JWK hmac = new HMACSecret(localSecret, LOCAL_SECRET_KEY_ID, true);
        KeySelector selector = new SingleKeySelector(hmac);
        JWTData<OfflineToken> jwtData = decode.decode(token, OfflineToken.class, selector, new OfflineTokenVerifier());
        return jwtData.getData();

    }

    private static class OfflineTokenVerifier implements JWTVerifier {

        @Override
        public boolean verify(JWSHeader header, JWTClaimsSet jwtClaimsSet) {
            return header.getCustomParams().containsKey("Octopus Offline");  // Fixme Constant
        }
    }
}
