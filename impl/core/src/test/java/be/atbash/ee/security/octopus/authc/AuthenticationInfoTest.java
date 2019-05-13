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
package be.atbash.ee.security.octopus.authc;

import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.util.codec.DefaultByteSource;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthenticationInfoTest {

    @Test
    public void standard() {
        UserPrincipal userPrincipal = new UserPrincipal("id", "atbash", "Atbash");
        AuthenticationInfo info = new AuthenticationInfo(userPrincipal, "credentials");
        assertThat(info.isExternalVerification()).isFalse();
        assertThat(info.isOneTimeAuthentication()).isFalse();
        assertThat(info.isHashedPassword()).isFalse();

        assertThat(info.getPrincipals().getPrimaryPrincipal()).isEqualTo(userPrincipal);
    }

    @Test
    public void external() {
        UserPrincipal userPrincipal = new UserPrincipal("id", "atbash", "Atbash");
        AuthenticationInfo info = new AuthenticationInfo(userPrincipal);
        assertThat(info.isExternalVerification()).isTrue();
        assertThat(info.isOneTimeAuthentication()).isFalse();

        assertThat(info.getPrincipals().getPrimaryPrincipal()).isEqualTo(userPrincipal);
    }

    @Test
    public void validatedAuthenticationToken() {
        UserPrincipal userPrincipal = new UserPrincipal("id", "atbash", "Atbash");
        AuthenticationInfo info = new AuthenticationInfo(userPrincipal, new SomeValidatedToken());
        assertThat(info.isExternalVerification()).isFalse();
        assertThat(info.isOneTimeAuthentication()).isTrue();

        assertThat(info.getPrincipals().getPrimaryPrincipal()).isEqualTo(userPrincipal);
    }

    @Test
    public void saltedPasword() {
        UserPrincipal userPrincipal = new UserPrincipal("id", "atbash", "Atbash");
        AuthenticationInfo info = new AuthenticationInfo(userPrincipal, "PW", DefaultByteSource.creator.bytes("TheSalt"));

        assertThat(info.isExternalVerification()).isFalse();
        assertThat(info.isOneTimeAuthentication()).isFalse();
        assertThat(info.isHashedPassword()).isTrue();


        assertThat(info.getPrincipals().getPrimaryPrincipal()).isEqualTo(userPrincipal);

    }

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