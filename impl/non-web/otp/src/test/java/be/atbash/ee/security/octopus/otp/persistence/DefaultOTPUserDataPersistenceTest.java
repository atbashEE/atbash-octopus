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
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class DefaultOTPUserDataPersistenceTest {

    @Test
    public void retrieveData() {
        DefaultOTPUserDataPersistence otpUserDataPersistence = new DefaultOTPUserDataPersistence();

        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "JUnit");
        OTPUserData userData = otpUserDataPersistence.retrieveData(userPrincipal);

        assertThat(userData).isNotNull();
        assertThat(userData.getKey()).hasSize(8);
        assertThat(userData.getValue()).isEqualTo(0);
    }

    @Test
    public void retrieveData_noCache() {
        DefaultOTPUserDataPersistence otpUserDataPersistence = new DefaultOTPUserDataPersistence();

        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "JUnit");
        OTPUserData userData1 = otpUserDataPersistence.retrieveData(userPrincipal);
        OTPUserData userData2 = otpUserDataPersistence.retrieveData(userPrincipal);

        assertThat(userData1.getKey()).isNotEqualTo(userData2.getKey());

    }

}