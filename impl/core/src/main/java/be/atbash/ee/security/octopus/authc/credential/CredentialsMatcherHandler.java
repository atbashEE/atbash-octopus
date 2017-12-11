/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.ee.security.octopus.util.order.CredentialsMatcherComparator;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import java.util.*;

/**
 *
 */
@ApplicationScoped
public class CredentialsMatcherHandler {

    @Inject
    private Instance<CredentialsMatcher> credentialsMatcherProvider;

    private List<CredentialsMatcher> matchers;

    @PostConstruct
    public void initMatchers() {
        matchers = new ArrayList<>();
        for (CredentialsMatcher credentialsMatcher : credentialsMatcherProvider.select()) {
            matchers.add(credentialsMatcher);
        }

        Collections.sort(matchers, new CredentialsMatcherComparator());
    }

    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        prepareMatchers();

        boolean result = false;
        if (token instanceof ValidatedAuthenticationToken) {
            return true;
        }

        Iterator<CredentialsMatcher> iterator = matchers.iterator();
        while (!result && iterator.hasNext()) {
            CredentialsMatcher matcher = iterator.next();
            result = matcher.doCredentialsMatch(token, info);
        }

        /*
        // FIXME
        //if (!(info instanceof ExternalPasswordAuthenticationInfo)) {
        iterator = octopusDefinedMatchers.iterator();
        while (!result && iterator.hasNext()) {
            CredentialsMatcher matcher = iterator.next();
            result = matcher.doCredentialsMatch(token, info);
        }
        //}
        */

        // True means the user/caller is allowed and there is no way in stopping him/her anymore further on in the code.
        return result;
    }

    private void prepareMatchers() {
        if (matchers == null) {
            matchers = new ArrayList<>();
            for (CredentialsMatcher credentialsMatcher : ServiceLoader.load(CredentialsMatcher.class)) {
                matchers.add(credentialsMatcher);
            }
        }
    }

}
