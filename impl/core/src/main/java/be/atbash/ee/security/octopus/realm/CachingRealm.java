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
package be.atbash.ee.security.octopus.realm;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authc.AbstractAuthenticator;
import be.atbash.ee.security.octopus.authc.LogoutAware;
import be.atbash.ee.security.octopus.authz.AuthorizerDataProvider;
import be.atbash.ee.security.octopus.cache.Cache;
import be.atbash.ee.security.octopus.cache.CacheManager;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.util.Nameable;
import be.atbash.ee.security.octopus.util.OctopusCollectionUtils;
import be.atbash.util.CDIUtils;
import be.atbash.util.reflection.CDICheck;
import be.atbash.util.reflection.ClassUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;

/**
 * A very basic abstract extension point for the {@link Realm} interface that provides caching support for subclasses.
 * <p/>
 * It also provides a convenience method,
 * {@link #getAvailablePrincipal(PrincipalCollection)}, which is useful across all
 * realm subclasses for obtaining a realm-specific principal/identity.
 * <p/>
 * All actual Realm method implementations are left to subclasses.
 *
 * @see #clearCache(PrincipalCollection)
 * @see #onLogout(PrincipalCollection)
 * @see #getAvailablePrincipal(PrincipalCollection)
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.realm.CachingRealm"})
public abstract class CachingRealm extends AbstractAuthenticator implements AuthorizerDataProvider, Nameable, LogoutAware {

    private static final Logger log = LoggerFactory.getLogger(CachingRealm.class);

    //TODO - complete JavaDoc

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private boolean cachingEnabled;

    private CacheManager cacheManager;

    protected OctopusCoreConfiguration configuration;

    /**
     * Default no-argument constructor that defaults
     * {@link #isCachingEnabled() cachingEnabled} (for general caching) to {@code true} and sets a
     * default {@link #getName() name} based on the class name.
     * <p/>
     * Note that while in general, caching may be enabled by default, subclasses have control over
     * if specific caching is enabled.
     */
    CachingRealm() {
        cachingEnabled = true;
    }

    protected void init() {
        configuration = OctopusCoreConfiguration.getInstance();

        cacheManager = instantiateCacheManager();
    }

    private CacheManager instantiateCacheManager() {
        Class<? extends CacheManager> cacheManagerClass = configuration.getCacheManagerClass();
        if (CDICheck.withinContainer() && cacheManagerClass.getAnnotation(ApplicationScoped.class) != null) {
            return CDIUtils.retrieveInstance(cacheManagerClass);
        } else {
            return ClassUtils.newInstance(cacheManagerClass);
        }
    }

    CacheManager getCacheManager() {
        return cacheManager;
    }

    /**
     * Returns {@code true} if caching should be used if a {@link CacheManager} has been
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) configured}, {@code false} otherwise.
     * <p/>
     * The default value is {@code true} since the large majority of Realms will benefit from caching if a CacheManager
     * has been configured.  However, memory-only realms should set this value to {@code false} since they would
     * manage account data in memory already lookups would already be as efficient as possible.
     *
     * @return {@code true} if caching will be globally enabled if a {@link CacheManager} has been
     * configured, {@code false} otherwise
     */
    public boolean isCachingEnabled() {
        return cachingEnabled;
    }

    /**
     * Sets whether or not caching should be used if a {@link CacheManager} has been
     * {@link #setCacheManager(CacheManager) configured}.
     *
     * @param cachingEnabled whether or not to globally enable caching for this realm.
     */
    public void setCachingEnabled(boolean cachingEnabled) {
        this.cachingEnabled = cachingEnabled;
    }

    /**
     * Template method that may be implemented by subclasses should they wish to react to a
     * {@link CacheManager} instance being set on the realm instance via the
     * {@link #setCacheManager(CacheManager)} mutator.
     */
    protected void afterCacheManagerSet() {
    }

    /**
     * If caching is enabled, this will clear any cached data associated with the specified account identity.
     * Subclasses are free to override for additional behavior, but be sure to call {@code super.onLogout} first.
     * <p/>
     * This default implementation merely calls {@link #clearCache(PrincipalCollection)}.
     *
     * @param principals the application-specific Subject/user identifier that is logging out.
     * @see #clearCache(PrincipalCollection)
     */
    public void onLogout(PrincipalCollection principals) {
        super.onLogout(principals);
        clearCache(principals);
    }

    /**
     * Clears out any cached data associated with the specified account identity/identities.
     * <p/>
     * This implementation will return quietly if the principals argument is null or empty.  Otherwise it delegates
     * to {@link #doClearCache(PrincipalCollection)}.
     *
     * @param principals the principals of the account for which to clear any cached data.
     */
    protected void clearCache(PrincipalCollection principals) {
        if (!OctopusCollectionUtils.isEmpty(principals)) {
            doClearCache(principals);
            log.trace("Cleared cache entries for account with principals [{}]", principals);
        }
    }

    /**
     * This implementation does nothing - it is a template to be overridden by subclasses if necessary.
     *
     * @param principals principals the principals of the account for which to clear any cached data.
     */
    protected void doClearCache(PrincipalCollection principals) {
        // FIXME
    }

    public <T> Cache<String, T> retrieveCache(CacheName cacheName) {
        return cacheManager.getCache(cacheName.getName());
    }

    public enum CacheName {
        OAUTH2_TOKEN("OAuth2.AuthenticationToken");

        private String name;

        CacheName(String name) {

            this.name = name;
        }

        public String getName() {
            return name;
        }
    }
}
