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
package be.atbash.ee.security.octopus.otp;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.AuthenticationInfoProvider;
import be.atbash.ee.security.octopus.authc.AuthenticationStrategy;
import be.atbash.ee.security.octopus.authc.SimpleAuthenticationInfo;
import be.atbash.ee.security.octopus.otp.persistence.OTPUserDataPersistence;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.OTPToken;
import be.atbash.ee.security.octopus.twostep.TwoStepProvider;
import be.atbash.ee.security.octopus.util.order.ProviderOrder;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import static be.atbash.ee.security.octopus.OctopusConstants.OCTOPUS_TWO_STEP;

@ApplicationScoped
@ProviderOrder(-200)
public class OTPTwoStepProvider extends AuthenticationInfoProvider implements TwoStepProvider {

    @Inject
    private OTPProviderFactory otpProviderFactory;

    @Inject
    private OTPUserDataPersistence otpUserDataPersistence;

    @Inject
    private OTPValueSender OTPValueSender;

    // TODO Do we need a separate store for this?
    private Map<Serializable, String> otpValues = new HashMap<>();

    @Override
    public void startSecondStep(HttpServletRequest request, UserPrincipal userPrincipal) {
        OTPProvider provider = otpProviderFactory.retrieveOTPProvider();

        String otpValue = provider.generate(otpUserDataPersistence.retrieveData(userPrincipal));
        OTPValueSender.sendValue(userPrincipal, otpValue);
        otpValues.put(userPrincipal.getId(), otpValue);

    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        if (token instanceof OTPToken) {
            UserPrincipal userPrincipal = SecurityUtils.getSubject().getPrincipal();
            String value = otpValues.get(userPrincipal.getId());
            otpValues.remove(userPrincipal.getId()); // Make sure it can't be retrieved a second time!!
            // Wo when a wrong value is entered the first time, no second chance.

            userPrincipal.addUserInfo(OCTOPUS_TWO_STEP, Boolean.TRUE);
            return new SimpleAuthenticationInfo(userPrincipal, value);

        }
        return null;
    }

    @Override
    public AuthenticationStrategy getAuthenticationStrategy() {
        return AuthenticationStrategy.SUFFICIENT;
    }
}
