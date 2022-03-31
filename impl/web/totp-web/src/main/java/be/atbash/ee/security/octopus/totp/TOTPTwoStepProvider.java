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
package be.atbash.ee.security.octopus.totp;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.AuthenticationInfoProvider;
import be.atbash.ee.security.octopus.authc.AuthenticationStrategy;
import be.atbash.ee.security.octopus.otp.OTPProviderFactory;
import be.atbash.ee.security.octopus.otp.OTPUserData;
import be.atbash.ee.security.octopus.otp.persistence.OTPUserDataPersistence;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.OTPToken;
import be.atbash.ee.security.octopus.twostep.TwoStepProvider;
import be.atbash.ee.security.octopus.util.order.ProviderOrder;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;

@ApplicationScoped
@ProviderOrder(-150)
public class TOTPTwoStepProvider extends AuthenticationInfoProvider implements TwoStepProvider {

    @Inject
    private OTPProviderFactory otpProviderFactory;

    @Inject
    private OTPUserDataPersistence otpUserDataPersistence;

    @Override
    public void startSecondStep(HttpServletRequest request, UserPrincipal userPrincipal) {
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        if (token instanceof OTPToken) {
            UserPrincipal userPrincipal = SecurityUtils.getSubject().getPrincipal();

            OTPUserData data = otpUserDataPersistence.retrieveData(userPrincipal);
            return new AuthenticationInfo(userPrincipal, data);

        }
        return null;
    }

    @Override
    public AuthenticationStrategy getAuthenticationStrategy() {
        return AuthenticationStrategy.SUFFICIENT;
    }
}
