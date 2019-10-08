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
package be.atbash.ee.security.octopus.token;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.util.HmacSecretUtil;

import java.util.Base64;

import static be.atbash.ee.security.octopus.token.OfflineToken.LOCAL_SECRET_KEY_ID;

/**
 *
 */

public final class GenerateOfflineToken {

    private GenerateOfflineToken() {
    }

    public static String createFor(OfflineToken offlineToken, String localSecret) {

        JWTEncoder encoder = new JWTEncoder();

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withHeader("Octopus Offline", "v0.2")
                .withSecretKeyForSigning(HmacSecretUtil.generateSecretKey(LOCAL_SECRET_KEY_ID, Base64.getDecoder().decode(localSecret)))
                .build();

        return encoder.encode(offlineToken, parameters);
    }

}
