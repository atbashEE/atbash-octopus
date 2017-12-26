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
package be.atbash.ee.security.octopus.jwt.encoder;

import be.atbash.config.exception.ConfigurationException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.util.ByteUtils;

import javax.enterprise.context.ApplicationScoped;
import java.util.Set;

/**
 *
 */
@ApplicationScoped
public class HMACAlgorithmFactory {

    public JWSAlgorithm determineOptimalAlgorithm(byte[] secret) {
        JWSAlgorithm result = null;

        Set<JWSAlgorithm> algorithms = MACSigner.getCompatibleAlgorithms(ByteUtils.bitLength(secret));

        if (algorithms.contains(JWSAlgorithm.HS512)) {
            result = JWSAlgorithm.HS512;
        }
        if (result == null && algorithms.contains(JWSAlgorithm.HS384)) {
            result = JWSAlgorithm.HS384;
        }
        if (result == null && algorithms.contains(JWSAlgorithm.HS256)) {
            result = JWSAlgorithm.HS256;
        }

        if (result == null) {
            throw new ConfigurationException("Secret is too short for any JWS HMAC algorithm.");
        }
        return result;
    }
}
