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
package be.atbash.ee.security.octopus.realm;

import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.IncorrectDataToken;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FIXME, a lot of other tests are required.
 */

public class AuthenticatingRealmTest {

    private AuthenticatingRealm realm;

    @BeforeEach
    public void setup() {
        realm = new AuthorizingRealm() {
            @Override
            protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
                return null;
            }

            @Override
            protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
                return null;
            }

            @Override
            protected AuthenticationInfo doAuthenticate(AuthenticationToken token) throws AuthenticationException {
                return null;
            }
        };
    }

    @Test
    public void getAuthenticationInfo_clearWithUsernamePasswordToken() {
        UsernamePasswordToken token = new UsernamePasswordToken("JUnit", "Atbash".toCharArray());
        realm.getAuthenticationInfo(token);

        assertThat(token.getUsername()).isEqualTo("JUnit");
        assertThat(token.getPassword()).isNull();
    }

    @Test
    public void getAuthenticationInfo_clearWithToken() {
        AuthenticationToken token = new IncorrectDataToken("Message");
        realm.getAuthenticationInfo(token);

        // When no exception occurred, we know it can handle other types then UserNamePassword
    }

}