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
package be.atbash.ee.security.octopus.totp;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.credential.CredentialsMatcher;
import be.atbash.ee.security.octopus.otp.OTPProvider;
import be.atbash.ee.security.octopus.otp.OTPProviderFactory;
import be.atbash.ee.security.octopus.otp.OTPUserData;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.OTPToken;
import be.atbash.ee.security.octopus.totp.config.TOTPConfiguration;
import be.atbash.ee.security.octopus.util.order.CredentialsMatcherOrder;
import be.atbash.util.CDIUtils;

@CredentialsMatcherOrder(-50)
public class OTPCredentialsMatcher implements CredentialsMatcher {

    private OTPProvider otpProvider;

    private TOTPConfiguration totpConfiguration;

    public OTPCredentialsMatcher() {
        OTPProviderFactory otpProviderFactory = CDIUtils.retrieveInstance(OTPProviderFactory.class);
        otpProvider = otpProviderFactory.retrieveOTPProvider();

        totpConfiguration = CDIUtils.retrieveInstance(TOTPConfiguration.class);
    }

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        if (!(token instanceof OTPToken)) {
            return false;
        }
        OTPToken otpToken = (OTPToken) token;
        OTPUserData otpUserData = (OTPUserData) info.getCredentials();
        // info.getCredentials() OTPUserData
        //otpToken.getCredentials() entered by user


        return otpProvider.valid(otpUserData, totpConfiguration.getWindow(), otpToken.getCredentials().toString());
    }
}
