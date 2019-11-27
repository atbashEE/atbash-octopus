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
package be.atbash.ee.oauth2.sdk.util;


import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;

import java.util.List;
import java.util.Map;


/**
 * JSON Web Token (JWT) claims set utilities.
 */
public final class JWTClaimsSetUtils {


    /**
     * Creates a JWT claims set from the specified multi-valued parameters.
     * Single-valued parameters are mapped to a string claim. Multi-valued
     * parameters are mapped to a string array claim.
     *
     * @param params The multi-valued parameters. Must not be {@code null}.
     * @return The JWT claims set.
     */
    public static JWTClaimsSet toJWTClaimsSet(Map<String, List<String>> params) {

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

        for (Map.Entry<String, List<String>> en : params.entrySet()) {

            if (en.getValue().size() == 1) {

                String singleValue = en.getValue().get(0);
                builder.claim(en.getKey(), singleValue);

            } else if (en.getValue().size() > 0) {

                List<String> multiValue = en.getValue();
                builder.claim(en.getKey(), multiValue);
            }
        }

        return builder.build();
    }


    /**
     * Prevents public instantiation.
     */
    private JWTClaimsSetUtils() {
    }
}
