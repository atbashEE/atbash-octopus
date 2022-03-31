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
package be.atbash.ee.security.octopus.otp.persistence;

import be.atbash.ee.security.octopus.otp.OTPUserData;
import be.atbash.ee.security.octopus.subject.UserPrincipal;

import jakarta.enterprise.inject.Vetoed;
import java.security.SecureRandom;

/**
 *
 */
@Vetoed
public class DefaultOTPUserDataPersistence implements OTPUserDataPersistence {

    private SecureRandom secureRandom = new SecureRandom();

    @Override
    public OTPUserData retrieveData(UserPrincipal userPrincipal) {
        byte[] secret = defineSecretFor();
        // The 2 parameter is only used for HOTP and there it has the default value of 0.
        return new OTPUserData(secret, 0L);
    }

    private byte[] defineSecretFor() {
        byte[] result = new byte[8];  // TODO Since this is not production usage class, I guess we don't need to make this configurable.
        // Don't forget to mention it in the docs.
        secureRandom.nextBytes(result);
        return result;
    }

    @Override
    public void storeData(UserPrincipal userPrincipal, OTPUserData otpUserData) {

    }
}
