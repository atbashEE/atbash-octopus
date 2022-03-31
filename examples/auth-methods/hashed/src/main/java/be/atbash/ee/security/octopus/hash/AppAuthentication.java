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
package be.atbash.ee.security.octopus.hash;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.AuthenticationInfoProvider;
import be.atbash.ee.security.octopus.crypto.hash.SaltHashingUtil;
import be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class AppAuthentication extends AuthenticationInfoProvider {

    private int principalId = 0;

    @Inject
    private SaltHashingUtil saltHashingUtil;

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        if (token instanceof UsernamePasswordToken) {
            UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(principalId++).name(token.getPrincipal().toString());
            // Best practice is that each user has his own salt value. So we create a salt here for each checks to simulate that.
            // See also the saltLength parameter for the length of this salt.
            byte[] salt = saltHashingUtil.nextSalt();
            authenticationInfoBuilder.salt(salt);
            // TODO: Change for production. Here we use username as password
            String hashedPassword = saltHashingUtil.hash(usernamePasswordToken.getUsername().toCharArray(), salt);
            authenticationInfoBuilder.password(hashedPassword);
            return authenticationInfoBuilder.build();
        }
        return null;
    }

}
