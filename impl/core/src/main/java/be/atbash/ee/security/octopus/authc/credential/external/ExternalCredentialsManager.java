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
package be.atbash.ee.security.octopus.authc.credential.external;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.credential.external.ldap.LDAPCredentialsMatcher;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;

import jakarta.enterprise.context.ApplicationScoped;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

@ApplicationScoped
public class ExternalCredentialsManager {

    private List<ExternalCredentialsMatcher> credentialsMatchers;

    public boolean checkValidCredentials(AuthenticationInfo info, UsernamePasswordToken token) {
        prepareMatchers();
        boolean result = false;

        for (ExternalCredentialsMatcher matcher : credentialsMatchers) {
            if (matcher.areCredentialsValid(info, token.getPassword())) {
                result = true;
                break;
            }
        }
        return result;
    }

    private void prepareMatchers() {
        if (credentialsMatchers == null) {

            credentialsMatchers = new ArrayList<>();
            for (ExternalCredentialsMatcher externalMatcher : ServiceLoader.load(ExternalCredentialsMatcher.class)) {
                externalMatcher.init();
                credentialsMatchers.add(externalMatcher);
            }
            if (credentialsMatchers.isEmpty()) {
                LDAPCredentialsMatcher ldapCredentialsMatcher = new LDAPCredentialsMatcher();
                ldapCredentialsMatcher.init();
                credentialsMatchers.add(ldapCredentialsMatcher);
            }
        }

    }
}
