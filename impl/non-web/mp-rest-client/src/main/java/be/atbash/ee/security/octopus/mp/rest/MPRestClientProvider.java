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
package be.atbash.ee.security.octopus.mp.rest;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.mp.config.MPRestClientConfiguration;
import be.atbash.ee.security.octopus.mp.token.MPToken;
import be.atbash.ee.security.octopus.subject.PrincipalManager;
import be.atbash.util.CDIUtils;
import be.atbash.util.StringUtils;
import be.atbash.util.CDICheck;

import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import java.io.IOException;

/**
 *
 */

public class MPRestClientProvider implements ClientRequestFilter {
    // Class name used in a string within OctopusRestClientBuilderListener. Don't refactor unless you change that class!!

    private JWTEncoder jwtEncoder;

    private KeySelector keySelector;

    private MPRestClientConfiguration mpRestClientConfiguration = MPRestClientConfiguration.getInstance();

    @Override
    public void filter(ClientRequestContext clientRequestContext) throws IOException {
        checkDependencies();
        MPToken mpToken = PrincipalManager.getInstance().convert(MPToken.class);

        SelectorCriteria criteria;
        String keyId = mpRestClientConfiguration.getKeyId();
        if (StringUtils.isEmpty(keyId)) {
            criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        } else {
            criteria = SelectorCriteria.newBuilder().withId(keyId).build();
        }

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(keySelector.selectAtbashKey(criteria))
                .build();
        String bearerHeader = jwtEncoder.encode(mpToken.getJWT(), parameters);

        clientRequestContext.getHeaders().add("authorization", "Bearer " + bearerHeader);
    }

    private void checkDependencies() {
        if (keySelector == null) {
            if (CDICheck.withinContainer()) {
                // Get CDI bean, allow for customization
                keySelector = CDIUtils.retrieveInstance(KeySelector.class);
                jwtEncoder = CDIUtils.retrieveInstance(JWTEncoder.class);
            } else {
                // Java SE
                keySelector = new KeySelector();
                jwtEncoder = new JWTEncoder();
            }
        }
    }

}
