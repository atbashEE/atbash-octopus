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

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.CredentialsException;
import be.atbash.ee.security.octopus.authc.UnknownAccountException;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.TokenBasedAuthorizationInfoProvider;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.crypto.hash.HashFactory;
import be.atbash.ee.security.octopus.crypto.hash.SaltHashingUtil;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.AuthorizationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.util.TestReflectionUtils;
import be.atbash.util.codec.Hex;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class OctopusOfflineRealmTest {

    private OctopusOfflineRealm realm;

    private SaltHashingUtil hashingUtil;

    @BeforeEach
    public void setup() throws IllegalAccessException {
        realm = OctopusOfflineRealm.getInstance();
        TestConfig.addConfigValue("authenticationInfoProvider.class", "be.atbash.ee.security.octopus.realm.TestAuthenticationInfoProvider");

        hashingUtil = SaltHashingUtil.getInstance();
        HashFactory factory = HashFactory.getInstance();
        TestReflectionUtils.injectDependencies(hashingUtil, OctopusCoreConfiguration.getInstance(), factory);

        factory.defineRealHashAlgorithmName("SHA-256");
    }

    @AfterEach
    public void cleanup() {
        TestConfig.resetConfig();
    }

    @Test
    public void doGetAuthenticationInfo_scenario1() {
        // Classic, no specific token
        AuthenticationToken token = new UsernamePasswordToken("JUnit", "Atbash".toCharArray());

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.principalId(1L);
        AuthenticationInfo info = builder.build();
        TestAuthenticationInfoProvider.authenticationInfo = info;

        AuthenticationInfo data = realm.doGetAuthenticationInfo(token);
        assertThat(data).isNotNull();
        assertThat(data).isSameAs(info);
        assertThat(realm.getAuthorizationCache().size()).isEqualTo(0);
    }

    @Test
    public void doGetAuthenticationInfo_scenario2() {
        // Not authenticated
        AuthenticationToken token = new UsernamePasswordToken("JUnit", "Atbash".toCharArray());

        TestAuthenticationInfoProvider.authenticationInfo = null;

        Assertions.assertThrows(UnknownAccountException.class, () -> realm.doGetAuthenticationInfo(token));

    }

    @Test
    public void doGetAuthenticationInfo_scenario3() {
        // Verify encoding
        AuthenticationToken token = new UsernamePasswordToken("JUnit", "Atbash".toCharArray());

        TestConfig.addConfigValue("hashAlgorithmName", "sha512");

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.principalId(1L);
        builder.password(Hex.encode("Atbash".getBytes()));
        AuthenticationInfo info = builder.build();
        TestAuthenticationInfoProvider.authenticationInfo = info;

        AuthenticationInfo data = realm.doGetAuthenticationInfo(token);
        assertThat(data).isNotNull();
        assertThat(data).isSameAs(info);
        assertThat(realm.getAuthorizationCache().size()).isEqualTo(0);

    }

    @Test
    public void doGetAuthenticationInfo_scenario4() {
        // Verify encoding, Failed encoding
        AuthenticationToken token = new UsernamePasswordToken("JUnit", "Atbash".toCharArray());

        TestConfig.addConfigValue("hashAlgorithmName", "sha512");

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.principalId(1L);
        builder.password("AZERTY"); // this is not a valid HEX
        AuthenticationInfo info = builder.build();
        TestAuthenticationInfoProvider.authenticationInfo = info;

        Assertions.assertThrows(CredentialsException.class, () -> realm.doGetAuthenticationInfo(token));

    }

    @Test
    public void doAuthenticate_scenario1() {
        // Classic, no specific token
        AuthenticationToken token = new UsernamePasswordToken("JUnit", "Atbash".toCharArray());

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.principalId(1L);
        builder.password("Atbash".toCharArray());
        AuthenticationInfo info = builder.build();
        TestAuthenticationInfoProvider.authenticationInfo = info;

        AuthenticationInfo data = realm.doAuthenticate(token);
        assertThat(data).isNotNull();
        assertThat(data).isSameAs(info);
        assertThat(realm.getAuthorizationCache().size()).isEqualTo(0);
    }

    @Test
    public void doAuthenticate_scenario2() {
        // Not authenticated
        AuthenticationToken token = new UsernamePasswordToken("JUnit", "Atbash".toCharArray());

        TestAuthenticationInfoProvider.authenticationInfo = null;

        Assertions.assertThrows(UnknownAccountException.class, () -> realm.doAuthenticate(token));

    }

    @Test
    public void doAuthenticate_scenario3() {
        // Verify encoding
        AuthenticationToken token = new UsernamePasswordToken("JUnit", "Atbash".toCharArray());

        TestConfig.addConfigValue("hashAlgorithmName", "SHA-256");

        byte[] salt = hashingUtil.nextSalt();

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.principalId(1L);
        builder.salt(salt);

        builder.password(hashingUtil.hash("Atbash".toCharArray(), salt));

        AuthenticationInfo info = builder.build();
        TestAuthenticationInfoProvider.authenticationInfo = info;

        AuthenticationInfo data = realm.doAuthenticate(token);
        assertThat(data).isNotNull();
        assertThat(data).isSameAs(info);
        assertThat(realm.getAuthorizationCache().size()).isEqualTo(0);

    }

    @Test
    public void doAuthenticate_scenario4() {
        // Verify encoding, Failed encoding
        AuthenticationToken token = new UsernamePasswordToken("JUnit", "Atbash".toCharArray());

        TestConfig.addConfigValue("hashAlgorithmName", "sha512");

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.principalId(1L);
        builder.password("AZERTY"); // this is not a valid HEX
        AuthenticationInfo info = builder.build();
        TestAuthenticationInfoProvider.authenticationInfo = info;

        Assertions.assertThrows(CredentialsException.class, () -> realm.doAuthenticate(token));

    }

    @Test
    public void doAuthenticate_scenario5() {
        // authentication is also authorization token
        AuthenticationToken token = new AllToken();

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.principalId(1L);
        builder.password("AtbashToken");
        AuthenticationInfo info = builder.build();
        TestAuthenticationInfoProvider.authenticationInfo = info;

        System.setProperty("atbash.utils.cdi.check", "false");  // disable CDI

        AuthenticationInfo data = realm.doAuthenticate(token);
        assertThat(data).isNotNull();
        // Check if authorization info is set into cache
        assertThat(realm.getAuthorizationCache().size()).isEqualTo(1);
        AuthorizationInfo authorizationInfo = realm.getAuthorizationCache().get(new UserPrincipal(1L, null, null));
        assertThat(authorizationInfo).isNotNull();
        assertThat(authorizationInfo.getStringPermissions()).containsOnly("allToken");

    }

    @Test
    public void doAuthenticate_scenario6() {
        // authentication info contains validatedAuthenticationToken
        AuthenticationToken token = new UsernamePasswordToken("JUnit", "Atbash".toCharArray());

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.principalId(1L);
        builder.token(new ValidatedToken());
        AuthenticationInfo info = builder.build();
        TestAuthenticationInfoProvider.authenticationInfo = info;

        System.setProperty("atbash.utils.cdi.check", "false");  // disable CDI

        AuthenticationInfo data = realm.doAuthenticate(token);
        assertThat(data).isNotNull();
        // Check if authorization info is set into cache
        assertThat(realm.getAuthorizationCache().size()).isEqualTo(1);
        AuthorizationInfo authorizationInfo = realm.getAuthorizationCache().get(new UserPrincipal(1L, null, null));
        assertThat(authorizationInfo).isNotNull();
        assertThat(authorizationInfo.getStringPermissions()).containsOnly("validatedToken");

    }

    public class AllToken implements ValidatedAuthenticationToken, AuthorizationToken {

        @Override
        public Object getPrincipal() {
            return null;
        }

        @Override
        public Object getCredentials() {
            return "AtbashToken";
        }

        @Override
        public Class<? extends TokenBasedAuthorizationInfoProvider> authorizationProviderClass() {
            return TestTokenBasedAuthorizationInfoProvider.class;
        }
    }

    public class ValidatedToken implements ValidatedAuthenticationToken, AuthorizationToken {

        @Override
        public Object getPrincipal() {
            return null;
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Class<? extends TokenBasedAuthorizationInfoProvider> authorizationProviderClass() {
            return TestTokenBasedAuthorizationInfoProvider.class;
        }
    }

    public static class TestTokenBasedAuthorizationInfoProvider implements TokenBasedAuthorizationInfoProvider {

        @Override
        public AuthorizationInfo getAuthorizationInfo(AuthorizationToken token) {
            if (token instanceof AllToken) {
                AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();
                builder.addPermission("allToken");
                return builder.build();
            }
            if (token instanceof ValidatedToken) {
                AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();
                builder.addPermission("validatedToken");
                return builder.build();
            }
            return null;
        }
    }
}