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
package be.atbash.ee.security.octopus.jsf.totp.data;

import be.atbash.ee.security.octopus.otp.OTPUserData;
import be.atbash.ee.security.octopus.otp.persistence.OTPUserDataPersistence;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.util.codec.Base32Codec;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class DemoOTPUserDataPersistence implements OTPUserDataPersistence {

    @Inject
    private UserBoundary userBoundary;

    @Override
    public OTPUserData retrieveData(UserPrincipal userPrincipal) {
        UserData userData = userBoundary.getData(userPrincipal.getUserName());
        return new OTPUserData(Base32Codec.decode(userData.getSecret()), 0L);
    }

    @Override
    public void storeData(UserPrincipal userPrincipal, OTPUserData otpUserData) {

    }
}
