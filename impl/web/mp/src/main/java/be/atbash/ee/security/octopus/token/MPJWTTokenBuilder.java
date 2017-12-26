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

import be.atbash.ee.security.octopus.config.MPConfiguration;
import be.atbash.ee.security.octopus.util.duration.PeriodUtil;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.annotation.PostConstruct;
import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

/**
 *
 */
@Dependent
public class MPJWTTokenBuilder {

    @Inject
    private MPConfiguration mpConfiguration;

    private MPJWTToken token;

    @PostConstruct
    public void init() {
        token = new MPJWTToken();
    }

    public MPJWTTokenBuilder setIssuer(String issuer) {
        token.setIss(issuer);
        return this;
    }

    public MPJWTTokenBuilder setAudience(String audience) {
        token.setAud(audience);
        return this;
    }

    public MPJWTTokenBuilder setUniqueIdentifier(String id) {
        token.setJti(id);
        return this;
    }

    public MPJWTTokenBuilder setExpirationTime(Date expiration) {
        Objects.requireNonNull(expiration, "Expiration parameter must be non null");
        token.setExp(expiration.getTime());
        return this;
    }

    public MPJWTTokenBuilder setExpirationPeriod(String expiration) {
        int seconds = PeriodUtil.defineSecondsInPeriod(expiration);

        token.setExp(new Date().getTime() + seconds * 1000);
        return this;
    }

    public MPJWTTokenBuilder setIssuedAtTime(Date issued) {
        Objects.requireNonNull(issued, "'Issued At time' parameter must be non null");
        token.setIat(issued.getTime());
        return this;
    }

    public MPJWTTokenBuilder setSubject(String subject) {
        token.setSub(subject);
        return this;
    }

    public MPJWTTokenBuilder setUniquePrincipalName(String principalName) {
        token.setUpn(principalName);
        return this;
    }

    public MPJWTTokenBuilder addGroup(String groupName) {
        if (token.getGroups() == null) {
            token.setGroups(new ArrayList<String>());
        }
        this.token.getGroups().add(groupName);
        return this;
    }

    public MPJWTToken build() {
        useDefaults();
        validate();

        MPJWTToken result;
        try {
            result = (MPJWTToken) token.clone();
        } catch (CloneNotSupportedException e) {
            throw new AtbashUnexpectedException(e);
        }

        init();

        return result;
    }

    private void validate() {
        if (!StringUtils.hasText(token.getIss())) {
            throw new MissingClaimMPJWTTokenException("No value for 'iss'");
        }
        if (!StringUtils.hasText(token.getAud())) {
            throw new MissingClaimMPJWTTokenException("No value for 'aud'");
        }
        if (token.getExp() == null) {
            throw new MissingClaimMPJWTTokenException("No value for 'exp'");
        }
        if (!StringUtils.hasText(token.getSub()) && !StringUtils.hasText(token.getUpn())) {
            throw new MissingClaimMPJWTTokenException("No value for 'sub' and 'upn'");
        }
    }

    private void useDefaults() {
        if (!StringUtils.hasText(token.getIss())) {
            token.setIss(mpConfiguration.getIssuer());
        }

        if (!StringUtils.hasText(token.getAud())) {
            token.setAud(mpConfiguration.getAudience());
        }

        if (token.getIat() == null) {
            token.setIat(new Date().getTime());
        }

        if (token.getExp() == null) {
            String expirationTime = mpConfiguration.getExpirationTime();
            if (token.getIat() != null && StringUtils.hasText(expirationTime)) {
                token.setExp(token.getIat() + PeriodUtil.defineSecondsInPeriod(expirationTime) * 1000);
            }

        }

        if (token.getJti() == null) {
            // TODO Is this OK?
            token.setJti(UUID.randomUUID().toString());
        }

    }
}