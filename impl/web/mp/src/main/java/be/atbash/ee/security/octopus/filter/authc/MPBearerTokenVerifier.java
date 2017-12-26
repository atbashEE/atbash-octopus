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
package be.atbash.ee.security.octopus.filter.authc;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.config.MPConfiguration;
import be.atbash.ee.security.octopus.jwt.decoder.JWTVerifier;
import be.atbash.util.StringUtils;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.Date;

/**
 *
 */
@ApplicationScoped
public class MPBearerTokenVerifier implements JWTVerifier {

    @Inject
    private MPConfiguration mpConfiguration;

    @PostConstruct
    public void init() {
        if (!StringUtils.hasText(mpConfiguration.getAudience())) {
            throw new ConfigurationException("Parameter mp.aud is required");
        }
    }

    @Override
    public boolean verify(JWSHeader header, JWTClaimsSet jwtClaimsSet) {
        boolean result = true;
        if (!jwtClaimsSet.getAudience().contains(mpConfiguration.getAudience())) {
            // TODO Log
            result = false;
        }

        if (jwtClaimsSet.getExpirationTime().before(new Date())) {
            // TODO Log
            result = false;
        }
        return result;
    }
}
