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
package be.atbash.ee.security.octopus.realm;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.SimpleAuthenticationInfo;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class AuthenticationInfoBuilderTest {

    @Test
    public void token_WithPassword() {
        try {
            new AuthenticationInfoBuilder().password("ThePassword").token(new SomeValidatedToken());
        } catch (AtbashIllegalActionException e) {
            assertThat(e.getMessage()).startsWith("(OCT-DEV-002)");
        }

    }

    @Test
    public void nullToken_WithPassword() {

        new AuthenticationInfoBuilder().password("ThePassword").token(null);

    }

    @Test
    public void password_WithToken() {
        try {
            new AuthenticationInfoBuilder().token(new SomeValidatedToken()).password("ThePassword");
        } catch (AtbashIllegalActionException e) {
            assertThat(e.getMessage()).startsWith("(OCT-DEV-003)");
        }
    }

    @Test
    public void nullPassword_WithToken() {

        new AuthenticationInfoBuilder().token(new SomeValidatedToken()).password(null);

    }

    @Test
    public void principalId_null() {
        try {
            new AuthenticationInfoBuilder().principalId(null);
        } catch (AtbashIllegalActionException e) {
            assertThat(e.getMessage()).startsWith("(OCT-DEV-004)");
        }
    }

    @Test
    public void build_principalIdRequired() {
        try {
            new AuthenticationInfoBuilder().build();
        } catch (AtbashIllegalActionException e) {
            assertThat(e.getMessage()).startsWith("(OCT-DEV-004)");
        }
    }

    @Test
    public void build_minimal() {
        AuthenticationInfo info = new AuthenticationInfoBuilder().principalId(1L).build();

        assertThat(info).isNotNull();
        assertThat(info.getPrincipals()).isNotNull();
        assertThat(info.getPrincipals()).isNotEmpty();
        assertThat(info.getPrincipals().getPrimaryPrincipal()).isNotNull();
        assertThat(info.getPrincipals().getPrimaryPrincipal()).isInstanceOf(UserPrincipal.class);

        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();
        assertThat(userPrincipal.getId()).isEqualTo(1L);

    }

    @Test
    public void build_classic() {
        AuthenticationInfo info = new AuthenticationInfoBuilder().principalId(2L)
                .userName("JUnit").name("Atbash").build();

        assertThat(info).isNotNull();
        assertThat(info.getPrincipals()).isNotEmpty();
        assertThat(info.getPrincipals().getPrimaryPrincipal()).isInstanceOf(UserPrincipal.class);

        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();
        assertThat(userPrincipal.getId()).isEqualTo(2L);
        assertThat(userPrincipal.getUserName()).isEqualTo("JUnit");
        assertThat(userPrincipal.getName()).isEqualTo("Atbash");

    }

    @Test
    public void build_userInfo() {
        Map<String, String> data = new HashMap<>();
        data.put("key1", "value1");
        data.put("key2", "value2");
        AuthenticationInfo info = new AuthenticationInfoBuilder().principalId(1L)
                .addUserInfo("key", 321L)
                .addUserInfo(data)
                .build();

        assertThat(info).isNotNull();
        assertThat(info.getPrincipals()).isNotEmpty();
        assertThat(info.getPrincipals().getPrimaryPrincipal()).isInstanceOf(UserPrincipal.class);

        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();
        assertThat(userPrincipal.getUserInfo("key")).isEqualTo(321L);
        assertThat(userPrincipal.getUserInfo("key2")).isEqualTo("value2");

        assertThat(userPrincipal.getInfo()).hasSize(3);

    }

    @Test
    public void build_withPassword() {
        AuthenticationInfo info = new AuthenticationInfoBuilder().principalId(1L)
                .password("topSecret")
                .build();

        assertThat(info).isNotNull();
        assertThat(info).isInstanceOf(SimpleAuthenticationInfo.class);

        SimpleAuthenticationInfo simpleAuthenticationInfo = (SimpleAuthenticationInfo) info;
        assertThat(simpleAuthenticationInfo.getCredentials()).isEqualTo("topSecret");
        assertThat(simpleAuthenticationInfo.getCredentialsSalt()).isNull();
        assertThat(simpleAuthenticationInfo.isOneTimeAuthentication()).isFalse();
        assertThat(simpleAuthenticationInfo.getValidatedToken()).isNull();
    }

    @Test
    public void build_withPasswordAsObject() {
        AuthenticationInfo info = new AuthenticationInfoBuilder().principalId(1L)
                .password(321L)
                .build();

        assertThat(info).isNotNull();
        assertThat(info).isInstanceOf(SimpleAuthenticationInfo.class);

        SimpleAuthenticationInfo simpleAuthenticationInfo = (SimpleAuthenticationInfo) info;
        assertThat(simpleAuthenticationInfo.getCredentials()).isEqualTo(321L);
        assertThat(simpleAuthenticationInfo.isOneTimeAuthentication()).isFalse();
        assertThat(simpleAuthenticationInfo.getValidatedToken()).isNull();
    }

    @Test
    public void build_withPasswordAndSalt() {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        AuthenticationInfo info = new AuthenticationInfoBuilder().principalId(1L)
                .password("topSecret")
                .salt(salt)
                .build();

        assertThat(info).isNotNull();
        assertThat(info).isInstanceOf(SimpleAuthenticationInfo.class);

        SimpleAuthenticationInfo simpleAuthenticationInfo = (SimpleAuthenticationInfo) info;
        assertThat(simpleAuthenticationInfo.getCredentials()).isEqualTo("topSecret");
        assertThat(simpleAuthenticationInfo.getCredentialsSalt().getBytes()).isEqualTo(salt);
        assertThat(simpleAuthenticationInfo.isOneTimeAuthentication()).isFalse();
        assertThat(simpleAuthenticationInfo.getValidatedToken()).isNull();
    }

    @Test
    public void build_withToken() {
        AuthenticationInfo info = new AuthenticationInfoBuilder().principalId(1L)
                .token(new SomeValidatedToken())
                .build();

        assertThat(info).isNotNull();
        assertThat(info).isInstanceOf(SimpleAuthenticationInfo.class);

        SimpleAuthenticationInfo simpleAuthenticationInfo = (SimpleAuthenticationInfo) info;
        assertThat(simpleAuthenticationInfo.getCredentials()).isNull();
        assertThat(simpleAuthenticationInfo.getCredentialsSalt()).isNull();
        assertThat(simpleAuthenticationInfo.isOneTimeAuthentication()).isTrue();
        assertThat(simpleAuthenticationInfo.getValidatedToken()).isInstanceOf(SomeValidatedToken.class);
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