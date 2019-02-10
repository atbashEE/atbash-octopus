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
package be.atbash.ee.security.octopus.otp.persistence;

import be.atbash.ee.security.octopus.otp.OTPUserData;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import org.slf4j.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class DefaultOTPUserDataPersistence implements OTPUserDataPersistence {

    @Inject
    private Logger logger;

    private Map<Serializable, OTPUserData> storage;

    protected SecureRandom secureRandom;

    @PostConstruct
    public void init() {
        if (this.getClass().equals(DefaultOTPUserDataPersistence.class)) {
            // Only executed when no @Specialized bean is defined.
            logger.warn("Please provide your own CDI @Specialized bean of DefaultOTPUserDataPersistence for production purposes.");
            logger.warn("The DefaultOTPUserDataPersistence should not be used in production as it doesn't keep OTP secrets between restarts");
            storage = new HashMap<>();
        }
        secureRandom = new SecureRandom();

    }

    @Override
    public OTPUserData retrieveData(UserPrincipal userPrincipal) {
        OTPUserData result = storage.get(userPrincipal.getId());
        if (result == null) {
            byte[] secret = defineSecretFor(userPrincipal);
            result = new OTPUserData(secret, 0L);
            // The 2 parameter is only used for HOTP and there it has the default value of 0.

        }
        return result;
    }

    /**
     * When developer specializes this CDI bean, it is encouraged to overwrite this method.
     *
     * @param userPrincipal
     * @return
     */
    protected byte[] defineSecretFor(UserPrincipal userPrincipal) {
        byte[] result = new byte[8];  // TODO Since this is not production usage class, I guess we don't need to make this configurable.
        // Don't forget to mention it in the docs.
        secureRandom.nextBytes(result);
        return result;
    }

    @Override
    public void storeData(UserPrincipal userPrincipal, OTPUserData otpUserData) {

    }
}
