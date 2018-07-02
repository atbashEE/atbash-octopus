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
package be.atbash.ee.security.octopus.subject.support;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.SimpleAuthenticationInfo;
import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.mgt.StandardSecurityManager;
import be.atbash.ee.security.octopus.realm.AuthorizingRealm;
import be.atbash.ee.security.octopus.realm.OctopusOfflineRealm;
import be.atbash.ee.security.octopus.subject.*;
import be.atbash.ee.security.octopus.subject.SecurityManager;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class DefaultSubjectContextTest {

    private DefaultSubjectContext defaultSubjectContext;

    private AuthorizingRealm realm;

    @Before
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

        defaultSubjectContext = new DefaultSubjectContext(realm);
    }

    @After
    public void teardown() {
        TestConfig.resetConfig();
    }

    @Test
    public void resolveSecurityManager() {

        SecurityManager securityManager = defaultSubjectContext.resolveSecurityManager();
        assertThat(securityManager).isNotNull();
        assertThat(securityManager).isInstanceOf(StandardSecurityManager.class);
    }

    @Test
    public void resolveSecurityManager_setSecurityManager() {

        SecurityManager securityManager = defaultSubjectContext.resolveSecurityManager();
        assertThat(securityManager).isNotNull();

        SecurityManager securityManager2 = defaultSubjectContext.resolveSecurityManager();
        assertThat(securityManager2).isNotNull();

        assertThat(securityManager == securityManager2).isTrue();

    }

    @Test
    public void resolveSecurityManager_useAvailable() {
        defaultSubjectContext.setSecurityManager(new DummySecurityManager());

        SecurityManager securityManager = defaultSubjectContext.resolveSecurityManager();
        assertThat(securityManager).isNotNull();
        assertThat(securityManager).isInstanceOf(DummySecurityManager.class);
    }

    @Test
    public void resolvePrincipals_noPrincipalAvailable() {
        PrincipalCollection principals = defaultSubjectContext.resolvePrincipals();
        assertThat(principals).isNull();
    }

    @Test
    public void resolvePrincipals_fromAuthenticationInfo() {
        UserPrincipal principal = new UserPrincipal("id", "atbash", "Atbash");
        AuthenticationInfo info = new SimpleAuthenticationInfo(principal, "Credentials");
        defaultSubjectContext.setAuthenticationInfo(info);

        PrincipalCollection principals = defaultSubjectContext.resolvePrincipals();
        assertThat(principals).isNotNull();
        assertThat(principals.getPrimaryPrincipal()).isEqualTo(principal);
    }

    @Test
    public void resolvePrincipals_fromSubject() {
        UserPrincipal principal = new UserPrincipal("id", "atbash", "Atbash");
        PrincipalCollection principals = new PrincipalCollection(principal);
        Subject subject = new DelegatingSubject(principals, true, new StandardSecurityManager(SubjectFactory.getInstance(), OctopusOfflineRealm.getInstance()), realm);
        defaultSubjectContext.setSubject(subject);

        PrincipalCollection data = defaultSubjectContext.resolvePrincipals();
        assertThat(data).isNotNull();
        assertThat(data.getPrimaryPrincipal()).isEqualTo(principal);
    }

    @Test
    public void resolvePrincipals_setPrincipals() {
        UserPrincipal principal = new UserPrincipal("id", "atbash", "Atbash");
        PrincipalCollection principals = new PrincipalCollection(principal);
        defaultSubjectContext.setPrincipals(principals);

        PrincipalCollection data = defaultSubjectContext.resolvePrincipals();
        assertThat(data).isNotNull();
        assertThat(data.getPrimaryPrincipal()).isEqualTo(principal);
    }

    @Test
    public void resolvePrincipals_setPrincipalsHasPriority() {
        UserPrincipal principal = new UserPrincipal("id1", "atbash", "Atbash");
        PrincipalCollection principals = new PrincipalCollection(principal);
        defaultSubjectContext.setPrincipals(principals);

        UserPrincipal principal2 = new UserPrincipal("id2", "atbash", "Atbash");
        PrincipalCollection principals2 = new PrincipalCollection(principal2);
        Subject subject = new DelegatingSubject(principals2, true, new StandardSecurityManager(SubjectFactory.getInstance(), OctopusOfflineRealm.getInstance()), realm);
        defaultSubjectContext.setSubject(subject);

        UserPrincipal principal3 = new UserPrincipal("id3", "atbash", "Atbash");
        AuthenticationInfo info = new SimpleAuthenticationInfo(principal3, "Credentials");
        defaultSubjectContext.setAuthenticationInfo(info);

        PrincipalCollection data = defaultSubjectContext.resolvePrincipals();
        assertThat(data).isNotNull();
        assertThat(data.getPrimaryPrincipal()).isEqualTo(principal);
    }

    @Test
    public void resolvePrincipals_fromAuthenticationInfoIsSecond() {

        UserPrincipal principal2 = new UserPrincipal("id2", "atbash", "Atbash");
        PrincipalCollection principals2 = new PrincipalCollection(principal2);
        Subject subject = new DelegatingSubject(principals2, true, new StandardSecurityManager(SubjectFactory.getInstance(), OctopusOfflineRealm.getInstance()), realm);
        defaultSubjectContext.setSubject(subject);

        UserPrincipal principal3 = new UserPrincipal("id3", "atbash", "Atbash");
        AuthenticationInfo info = new SimpleAuthenticationInfo(principal3, "Credentials");
        defaultSubjectContext.setAuthenticationInfo(info);

        PrincipalCollection data = defaultSubjectContext.resolvePrincipals();
        assertThat(data).isNotNull();
        assertThat(data.getPrimaryPrincipal()).isEqualTo(principal3);
    }

    @Test
    public void resolveAuthenticated() {
        boolean authenticated = defaultSubjectContext.resolveAuthenticated();
        assertThat(authenticated).isFalse();
    }

    @Test
    public void resolveAuthenticated_fromAuthentication() {
        UserPrincipal principal3 = new UserPrincipal("id", "atbash", "Atbash");
        AuthenticationInfo info = new SimpleAuthenticationInfo(principal3, "Credentials");
        defaultSubjectContext.setAuthenticationInfo(info);

        boolean authenticated = defaultSubjectContext.resolveAuthenticated();
        assertThat(authenticated).isTrue();
    }

    @Test
    public void resolveAuthenticated_setAuthenticated() {
        defaultSubjectContext.setAuthenticated(true);

        boolean authenticated = defaultSubjectContext.resolveAuthenticated();
        assertThat(authenticated).isTrue();
    }

    private static class DummySecurityManager implements SecurityManager {

        @Override
        public Subject login(Subject subject, AuthenticationToken authenticationToken) throws AuthenticationException {
            return null;
        }

        @Override
        public void logout(Subject subject) {

        }

        @Override
        public Subject createSubject(SubjectContext context) {
            return null;
        }

        @Override
        public boolean isPermitted(PrincipalCollection principals, String permission) {
            return false;
        }

        @Override
        public boolean isPermitted(PrincipalCollection subjectPrincipal, Permission permission) {
            return false;
        }

        @Override
        public boolean[] isPermitted(PrincipalCollection subjectPrincipal, String... permissions) {
            return new boolean[0];
        }

        @Override
        public boolean[] isPermitted(PrincipalCollection subjectPrincipal, List<Permission> permissions) {
            return new boolean[0];
        }

        @Override
        public boolean isPermittedAll(PrincipalCollection subjectPrincipal, String... permissions) {
            return false;
        }

        @Override
        public boolean isPermittedAll(PrincipalCollection subjectPrincipal, Collection<Permission> permissions) {
            return false;
        }

        @Override
        public void checkPermission(PrincipalCollection subjectPrincipal, String permission) throws AuthorizationException {

        }

        @Override
        public void checkPermission(PrincipalCollection subjectPrincipal, Permission permission) throws AuthorizationException {

        }

        @Override
        public void checkPermissions(PrincipalCollection subjectPrincipal, String... permissions) throws AuthorizationException {

        }

        @Override
        public void checkPermissions(PrincipalCollection subjectPrincipal, Collection<Permission> permissions) throws AuthorizationException {

        }

        @Override
        public boolean hasRole(PrincipalCollection subjectPrincipal, String roleIdentifier) {
            return false;
        }

        @Override
        public boolean[] hasRoles(PrincipalCollection subjectPrincipal, List<String> roleIdentifiers) {
            return new boolean[0];
        }

        @Override
        public boolean hasAllRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers) {
            return false;
        }

        @Override
        public void checkRole(PrincipalCollection subjectPrincipal, String roleIdentifier) throws AuthorizationException {

        }

        @Override
        public void checkRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers) throws AuthorizationException {

        }

        @Override
        public void checkRoles(PrincipalCollection subjectPrincipal, String... roleIdentifiers) throws AuthorizationException {

        }
    }
}