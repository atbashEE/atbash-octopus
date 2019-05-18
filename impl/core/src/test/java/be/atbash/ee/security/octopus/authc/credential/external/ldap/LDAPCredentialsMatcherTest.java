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
package be.atbash.ee.security.octopus.authc.credential.external.ldap;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.util.BeanManagerFake;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFReader;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.HashSet;
import java.util.Set;

import static be.atbash.ee.security.octopus.OctopusConstants.AUTHORIZATION_INFO;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(MockitoJUnitRunner.class)
public class LDAPCredentialsMatcherTest {

    private static InMemoryDirectoryServer directoryServer;

    private BeanManagerFake beanManagerFake;

    private LDAPCredentialsMatcher credentialsMatcher;

    @BeforeClass
    public static void setupLDAP() {

        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=be");
            config.setListenerConfigs(
                    new InMemoryListenerConfig("myListener", null, 33389, null, null, null));

            directoryServer = new InMemoryDirectoryServer(config);

            directoryServer.importFromLDIF(true,
                    new LDIFReader(LDAPCredentialsMatcherTest.class.getResourceAsStream("/test.ldif")));

            directoryServer.startListening();
        } catch (
                LDAPException e) {
            throw new IllegalStateException(e);
        }
    }

    @AfterClass
    public static void destroy() {
        directoryServer.shutDown(true);
    }

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(new LDAPConfiguration(), LDAPConfiguration.class);
        beanManagerFake.registerBean(new OctopusCoreConfiguration(), OctopusCoreConfiguration.class);  // For the Groups test
        beanManagerFake.endRegistration();

        credentialsMatcher = new LDAPCredentialsMatcher();

        TestConfig.addConfigValue("ldap.url", "ldap://localhost:33389/");
    }

    @After
    public void cleanup() {
        beanManagerFake.deregistration();
        TestConfig.resetConfig();
    }


    @Test
    public void areCredentialsValid_direct_valid() {

        credentialsMatcher.init();

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.userName("rudy").principalId(1L);
        AuthenticationInfo info = builder.build();

        UserPrincipal primaryPrincipal = info.getPrincipals().getPrimaryPrincipal();
        assertThat(primaryPrincipal.getName()).isNull();

        boolean valid = credentialsMatcher.areCredentialsValid(info, "secret1".toCharArray());
        assertThat(valid).isTrue();
        assertThat(info.getPrincipals().getPrimaryPrincipal().getInfo()).containsKeys("uid", "sn");  // Some of the LDAP attributes that are copied over.
        assertThat(primaryPrincipal.getName()).isEqualTo("Rudy De Busscher"); // Name is set by ldap.caller.name

        AuthorizationInfo authorizationInfo = info.getPrincipals().getPrimaryPrincipal().getUserInfo(AUTHORIZATION_INFO);
        assertThat(authorizationInfo).isNull();

    }

    @Test
    public void areCredentialsValid_direct_invalid() {

        credentialsMatcher.init();

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.userName("rudy").principalId(1L);
        AuthenticationInfo info = builder.build();

        boolean valid = credentialsMatcher.areCredentialsValid(info, "wrong".toCharArray());
        assertThat(valid).isFalse();
    }

    @Test
    public void areCredentialsValid_direct_unknownAccount() {

        credentialsMatcher.init();

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.userName("JUnit").principalId(1L);
        AuthenticationInfo info = builder.build();

        boolean valid = credentialsMatcher.areCredentialsValid(info, "something".toCharArray());
        assertThat(valid).isFalse();
    }

    @Test
    public void areCredentialsValid_bind_valid() {

        TestConfig.addConfigValue("ldap.bindDN", "uid=user,ou=admin,dc=atbash,dc=be");
        TestConfig.addConfigValue("ldap.bindCredential", "topsecret");

        credentialsMatcher.init();

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.userName("rudy").principalId(1L);
        AuthenticationInfo info = builder.build();

        boolean valid = credentialsMatcher.areCredentialsValid(info, "secret1".toCharArray());
        assertThat(valid).isTrue();
    }

    @Test
    public void areCredentialsValid_groups_retrieved() {

        TestConfig.addConfigValue("ldap.groups.loaded", "GROUPS");

        credentialsMatcher.init();

        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        builder.userName("rudy").principalId(1L);
        AuthenticationInfo info = builder.build();

        UserPrincipal primaryPrincipal = info.getPrincipals().getPrimaryPrincipal();
        assertThat(primaryPrincipal.getName()).isNull();

        boolean valid = credentialsMatcher.areCredentialsValid(info, "secret1".toCharArray());
        assertThat(valid).isTrue();
        AuthorizationInfo authorizationInfo = info.getPrincipals().getPrimaryPrincipal().getUserInfo(AUTHORIZATION_INFO);
        assertThat(authorizationInfo).isNotNull();
        assertThat(authorizationInfo.getObjectPermissions()).isNotEmpty();

        Set<String> roles = new HashSet<>();
        for (Permission permission : authorizationInfo.getObjectPermissions()) {
            roles.add(permission.toString());
        }
        assertThat(roles).containsOnly(">bar<", ">foo<");

    }
}