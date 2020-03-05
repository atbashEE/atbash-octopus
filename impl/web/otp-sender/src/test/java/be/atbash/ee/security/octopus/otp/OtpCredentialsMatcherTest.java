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
package be.atbash.ee.security.octopus.otp;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.credential.CredentialsMatcher;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.OTPToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class OtpCredentialsMatcherTest {

    private CredentialsMatcher matcher = new OtpCredentialsMatcher();

    @Test
    public void doCredentialsMatch() {
        AuthenticationToken token = new OTPToken("123456");  // User value
        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "JUnit");
        AuthenticationInfo info = new AuthenticationInfo(userPrincipal, "123456", true);
        boolean match = matcher.doCredentialsMatch(token, info);

        assertThat(match).isTrue();
    }

    @Test
    public void doCredentialsMatch_noMatch() {
        AuthenticationToken token = new OTPToken("123456");  // User value
        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "JUnit");
        AuthenticationInfo info = new AuthenticationInfo(userPrincipal, "654321", true);
        boolean match = matcher.doCredentialsMatch(token, info);

        assertThat(match).isFalse();
    }

    @Test
    public void doCredentialsMatch_WrongToken() {
        AuthenticationToken token = new UsernamePasswordToken("Junit", "pass");
        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "JUnit");
        AuthenticationInfo info = new AuthenticationInfo(userPrincipal, "654321", true);
        boolean match = matcher.doCredentialsMatch(token, info);

        assertThat(match).isFalse();
    }

}