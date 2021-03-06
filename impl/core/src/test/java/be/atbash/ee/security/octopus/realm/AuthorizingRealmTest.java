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
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.AuthenticationListener;
import be.atbash.ee.security.octopus.authc.RemoteLogoutHandler;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.cache.Cache;
import be.atbash.ee.security.octopus.cache.CacheException;
import be.atbash.ee.security.octopus.cache.CacheManager;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

/**
 *
 */
@ExtendWith(MockitoExtension.class)
public class AuthorizingRealmTest {

    private BeanManagerFake beanManagerFake;

    @Mock
    private Cache authenticationCacheMock;

    @Mock
    private Cache authorizationCacheMock;

    @Mock
    private RemoteLogoutHandler remoteLogoutHandlerMock;

    @Captor
    private ArgumentCaptor<Object> authenticationCacheKeyCaptor;

    @Captor
    private ArgumentCaptor<Object> authorizationCacheKeyCaptor;

    @BeforeEach
    public void setup() {
        beanManagerFake = new BeanManagerFake();
        TestConfig.registerDefaultConverters();

        TestCacheManager.cacheMap.put(".authenticationCache", authenticationCacheMock);
        TestCacheManager.cacheMap.put(".authorizationCache", authorizationCacheMock);
    }

    @AfterEach
    public void cleanup() {
        beanManagerFake.deregistration();
        TestConfig.resetConfig();
    }

    @Test
    public void onLogout() {
        // Test
        // - AuthenticationListener called
        // - Caches cleared
        beanManagerFake.endRegistration();

        TestConfig.addConfigValue("cacheManager.class", TestCacheManager.class.getName());
        TestConfig.addConfigValue("cache.authentication.activate", "true");

        TestCachingRealm realm = new TestCachingRealm();
        realm.init();

        TestAuthenticationListener listener = new TestAuthenticationListener();
        Collection<AuthenticationListener> listeners = new ArrayList<>();
        listeners.add(listener);
        realm.setAuthenticationListeners(listeners);

        // Test functionality
        realm.onLogout(new PrincipalCollection(new UserPrincipal(1L, "Atbash", "Atbash")));

        // Listener called?
        assertThat(listener.getPrincipals()).isNotNull();

        // Caches cleared?
        verify(authenticationCacheMock).remove(authenticationCacheKeyCaptor.capture());
        verify(authorizationCacheMock).remove(authorizationCacheKeyCaptor.capture());

        Object captorValue = authenticationCacheKeyCaptor.getValue();
        assertThat(captorValue).isInstanceOf(UserPrincipal.class);
        UserPrincipal userPrincipal = (UserPrincipal) captorValue;
        assertThat(userPrincipal.getUserName()).isEqualTo("Atbash");
        Object key = authorizationCacheKeyCaptor.getValue();
        assertThat(key).isInstanceOf(PrincipalCollection.class);

        PrincipalCollection principalCollection = (PrincipalCollection) key;
        UserPrincipal primaryPrincipal = principalCollection.getPrimaryPrincipal();

        assertThat(primaryPrincipal.getUserName()).isEqualTo("Atbash");

    }

    @Test
    public void onLogout_withRemoteHandler() {
        beanManagerFake.endRegistration();

        TestConfig.addConfigValue("cacheManager.class", TestCacheManager.class.getName());
        TestConfig.addConfigValue("cache.authentication.activate", "true");

        TestCachingRealm realm = new TestCachingRealm();
        realm.init();

        TestAuthenticationListener listener = new TestAuthenticationListener();
        Collection<AuthenticationListener> listeners = new ArrayList<>();
        listeners.add(listener);
        realm.setAuthenticationListeners(listeners);

        // Test functionality
        UserPrincipal principal = new UserPrincipal(1L, "Atbash", "Atbash");
        principal.setRemoteLogoutHandler(remoteLogoutHandlerMock);
        realm.onLogout(new PrincipalCollection(principal));

        verify(remoteLogoutHandlerMock).onLogout(any(PrincipalCollection.class));
    }

    private static class TestCachingRealm extends AuthorizingRealm {

        @Override
        protected AuthenticationInfo doAuthenticate(AuthenticationToken token) throws AuthenticationException {
            return null;
        }

        @Override
        public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {
            return null;
        }

        @Override
        protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
            return null;
        }

        @Override
        public void setName(String name) {

        }

        @Override
        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
            return null;
        }
    }

    private static class TestAuthenticationListener implements AuthenticationListener {

        private PrincipalCollection principals;

        @Override
        public void onSuccess(AuthenticationToken token, AuthenticationInfo info) {

        }

        @Override
        public void onFailure(AuthenticationToken token, AuthenticationException ae) {

        }

        @Override
        public void onLogout(PrincipalCollection principals) {
            this.principals = principals;
        }

        PrincipalCollection getPrincipals() {
            return principals;
        }
    }

    public static class TestCacheManager implements CacheManager {

        static Map<String, Cache> cacheMap = new HashMap<>();

        @Override
        public <K, V> Cache<K, V> getCache(String name) throws CacheException {
            Cache<K, V> result = null;

            for (Map.Entry<String, Cache> entry : cacheMap.entrySet()) {
                if (name.contains(entry.getKey())) {
                    result = entry.getValue();
                }
            }
            return result;
        }
    }
}