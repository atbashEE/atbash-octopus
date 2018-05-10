/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class CredentialsMatcherHandlerTest {

    private CredentialsMatcherHandler matcher = new CredentialsMatcherHandler();

    @Test
    public void doCredentialsMatch() {
        AuthenticationToken token = new UsernamePasswordToken("Atbash", "Atbash".toCharArray());

        AuthenticationInfo info = new AuthenticationInfoBuilder().principalId(1L).password("Atbash").build();
        boolean match = matcher.doCredentialsMatch(token, info);

        assertThat(match).isTrue();

    }

    @Test
    public void doCredentialsMatch_wrongPassword() {
        AuthenticationToken token = new UsernamePasswordToken("Atbash", "Wrong".toCharArray());

        AuthenticationInfo info = new AuthenticationInfoBuilder().principalId(1L).password("Atbash").build();
        boolean match = matcher.doCredentialsMatch(token, info);

        assertThat(match).isFalse();

    }

    @Test
    public void doCredentialsMatch_ValidatedAuthenticationToken() {
        AuthenticationInfo info = new AuthenticationInfoBuilder().principalId(1L).build();
        boolean match = matcher.doCredentialsMatch(new SomeValidatedToken(), info);

        assertThat(match).isTrue();

    }

    @Test
    public void doCredentialsMatch_oneTimeAuthentication() {
        // The AuthenticationInfoProvider obtains a ValidatedToken based on the info within the UsernamePasswordToken
        // Like Keycloak Client credentials flow
        AuthenticationToken token = new UsernamePasswordToken("Atbash", "Wrong".toCharArray());

        AuthenticationInfo info = new AuthenticationInfoBuilder().principalId(1L).token(new SomeValidatedToken()).build();
        boolean match = matcher.doCredentialsMatch(token, info);

        assertThat(match).isTrue();

    }

    // TODO test for the wile loop of multiple matchers.

    private static class SomeValidatedToken implements ValidatedAuthenticationToken {

        @Override
        public Object getPrincipal() {
            return null;
        }

        @Override
        public Object getCredentials() {
            return null;
        }
    }
}