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
package be.atbash.ee.security.octopus.authc.credential;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.credential.external.ExternalCredentialsManager;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.ee.security.octopus.util.order.CredentialsMatcherComparator;
import be.atbash.util.exception.AtbashIllegalActionException;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.util.*;

/**
 *
 */
@ApplicationScoped
public class CredentialsMatcherHandler {

    private List<CredentialsMatcher> matchers;

    private ExternalCredentialsManager externalCredentialsManager;

    @PostConstruct
    public void initMatchers() {
        // TODO Is this needed since the prepareMatchers is also called when doCredentialsMatch is called!?
        prepareMatchers();
    }

    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        prepareMatchers();  // For the Java SE version

        boolean result = false;
        if (token instanceof ValidatedAuthenticationToken) {
            return true;
        }

        if (info.getValidatedToken() != null) {
            return true;
        }

        if (info.isExternalVerification()) {
            if (token instanceof UsernamePasswordToken) {
                result = externalCredentialsManager.checkValidCredentials(info, (UsernamePasswordToken) token);
            } else {
                throw new AtbashIllegalActionException("(OCT-DEV-012) With external password check, the AuthenticationToken must be of type UsernamePasswordToken");
            }
        } else {
            Iterator<CredentialsMatcher> iterator = matchers.iterator();
            while (!result && iterator.hasNext()) {
                CredentialsMatcher matcher = iterator.next();
                result = matcher.doCredentialsMatch(token, info);
            }

        }

        // True means the user/caller is allowed and there is no way in stopping him/her anymore further on in the code.
        return result;
    }

    private void prepareMatchers() {
        if (matchers == null) {
            matchers = new ArrayList<>();
            for (CredentialsMatcher credentialsMatcher : ServiceLoader.load(CredentialsMatcher.class)) {
                matchers.add(credentialsMatcher);
            }
            Collections.sort(matchers, new CredentialsMatcherComparator());

            externalCredentialsManager = new ExternalCredentialsManager();
        }
    }

}
