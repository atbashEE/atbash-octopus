/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.IncorrectCredentialsException;
import be.atbash.ee.security.octopus.authc.credential.CredentialsMatcherHandler;
import be.atbash.ee.security.octopus.cache.Cache;
import be.atbash.ee.security.octopus.cache.CacheManager;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A top-level abstract implementation of the <tt>Realm</tt> interface that only implements authentication support
 * (log-in) operations and leaves authorization (access control) behavior to subclasses.
 * <h2>Authentication Caching</h2>
 * For applications that perform frequent repeated authentication of the same accounts (e.g. as is often done in
 * REST or Soap applications that authenticate on every request), it might be prudent to enable authentication
 * caching to alleviate constant load on any back-end data sources.
 * <p/>
 * This feature is disabled by default to retain backwards-compatibility with Shiro 1.1 and earlier.  It may be
 * enabled by setting {@link #setAuthenticationCachingEnabled(boolean) authenticationCachingEnabled} = {@code true}
 * (and configuring Shiro with a {@link CacheManager} of course), but <b>NOTE:</b>
 * <p/>
 * <b>ONLY enable authentication caching if either of the following is true for your realm implementation:</b>
 * <ul>
 * <li>The {@link #doGetAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken) doGetAuthenticationInfo}
 * implementation returns {@code AuthenticationInfo} instances where the
 * {@link org.apache.shiro.authc.AuthenticationInfo#getCredentials() credentials} are securely obfuscated and NOT
 * plaintext (raw) credentials. For example,
 * if your realm references accounts with passwords, that the {@code AuthenticationInfo}'s
 * {@link org.apache.shiro.authc.AuthenticationInfo#getCredentials() credentials} are safely hashed and salted or otherwise
 * fully encrypted.<br/><br/></li>
 * <li>The {@link #doGetAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken) doGetAuthenticationInfo}
 * implementation returns {@code AuthenticationInfo} instances where the
 * {@link org.apache.shiro.authc.AuthenticationInfo#getCredentials() credentials} are plaintext (raw) <b>AND</b> the
 * cache region storing the {@code AuthenticationInfo} instances WILL NOT overflow to disk and WILL NOT transmit cache
 * entries over an unprotected (non TLS/SSL) network (as might be the case with a networked/distributed enterprise cache).
 * This should be the case even in private/trusted/corporate networks.</li>
 * </ul>
 * <p/>
 * These points are very important because if authentication caching is enabled, this abstract class implementation
 * will place AuthenticationInfo instances returned from the subclass implementations directly into the cache, for
 * example:
 * <pre>
 * cache.put(cacheKey, subclassAuthenticationInfoInstance);
 * </pre>
 * <p/>
 * Enabling authentication caching is ONLY safe to do if the above two scenarios apply.  It is NOT safe to enable under
 * any other scenario.
 * <p/>
 * When possible, always represent and store credentials in a safe form (hash+salt or encrypted) to eliminate plaintext
 * visibility.
 * <h3>Authentication Cache Invalidation on Logout</h3>
 * If authentication caching is enabled, this implementation will attempt to evict (remove) cached authentication data
 * for an account during logout.  This can only occur if the
 * {@link #getAuthenticationCacheKey(org.apache.shiro.authc.AuthenticationToken)} and
 * {@link #getAuthenticationCacheKey(org.apache.shiro.subject.PrincipalCollection)} methods return the exact same value.
 * <p/>
 * The default implementations of these methods expect that the
 * {@link org.apache.shiro.authc.AuthenticationToken#getPrincipal()} (what the user submits during login) and
 * {@link #getAvailablePrincipal(org.apache.shiro.subject.PrincipalCollection) getAvailablePrincipal} (what is returned
 * by the realm after account lookup) return
 * the same exact value.  For example, the user submitted username is also the primary account identifier.
 * <p/>
 * However, if your application uses, say, a username for end-user login, but returns a primary key ID as the
 * primary principal after authentication, then you will need to override either
 * {@link #getAuthenticationCacheKey(org.apache.shiro.authc.AuthenticationToken) getAuthenticationCacheKey(token)} or
 * {@link #getAuthenticationCacheKey(org.apache.shiro.subject.PrincipalCollection) getAuthenticationCacheKey(principals)}
 * (or both) to ensure that the same cache key can be used for either object.
 * <p/>
 * This guarantees that the same cache key used to cache the data during authentication (derived from the
 * {@code AuthenticationToken}) will be used to remove the cached data during logout (derived from the
 * {@code PrincipalCollection}).
 * <h4>Unmatching Cache Key Values</h4>
 * If the return values from {@link #getAuthenticationCacheKey(org.apache.shiro.authc.AuthenticationToken)} and
 * {@link #getAuthenticationCacheKey(org.apache.shiro.subject.PrincipalCollection)} are not identical, cached
 * authentication data removal is at the mercy of your cache provider settings.  For example, often cache
 * implementations will evict cache entries based on a timeToIdle or timeToLive (TTL) value.
 * <p/>
 * If this lazy eviction capability of the cache product is not sufficient and you want discrete behavior
 * (highly recommended for authentication data), ensure that the return values from those two methods are identical in
 * the subclass implementation.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.realm.AuthenticatingRealm"})
public abstract class AuthenticatingRealm extends CachingRealm {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(AuthenticatingRealm.class);

    private static final AtomicInteger INSTANCE_COUNT = new AtomicInteger();

    /**
     * The default suffix appended to the realm name used for caching authentication data.
     */
    private static final String DEFAULT_AUTHORIZATION_CACHE_SUFFIX = ".authenticationCache";

    /**
     * Credentials matcher used to determine if the provided credentials match the credentials stored in the data store.
     */
    @Inject
    private CredentialsMatcherHandler credentialsMatcher;

    private Cache<Object, AuthenticationInfo> authenticationCache;

    private boolean authenticationCachingEnabled;
    private String authenticationCacheName;

    public AuthenticatingRealm() {

        int instanceNumber = INSTANCE_COUNT.getAndIncrement();
        authenticationCacheName = getClass().getName() + DEFAULT_AUTHORIZATION_CACHE_SUFFIX;
        if (instanceNumber > 0) {
            authenticationCacheName = authenticationCacheName + "." + instanceNumber;
        }

    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * Sets an explicit {@link Cache} instance to use for authentication caching.  If not set and authentication
     * caching is {@link #isAuthenticationCachingEnabled() enabled}, any available
     * {@link #getCacheManager() cacheManager} will be used to acquire the cache instance if available.
     * <p/>
     * <b>WARNING:</b> Only set this property if safe caching conditions apply, as documented at the top
     * of this page in the class-level JavaDoc.
     *
     * @param authenticationCache an explicit {@link Cache} instance to use for authentication caching or
     *                            {@code null} if the cache should possibly be obtained another way.
     * @see #isAuthenticationCachingEnabled()
     */
    public void setAuthenticationCache(Cache<Object, AuthenticationInfo> authenticationCache) {
        // FIXME How to use?
        this.authenticationCache = authenticationCache;
    }

    /**
     * Returns a {@link Cache} instance to use for authentication caching, or {@code null} if no cache has been
     * set.
     *
     * @return a {@link Cache} instance to use for authentication caching, or {@code null} if no cache has been
     * set.
     * @see #setAuthenticationCache(org.apache.shiro.cache.Cache)
     * @see #isAuthenticationCachingEnabled()
     */
    public Cache<Object, AuthenticationInfo> getAuthenticationCache() {
        // FIXME How to use?
        return authenticationCache;
    }

    /**
     * Returns the name of a {@link Cache} to lookup from any available {@link #getCacheManager() cacheManager} if
     * a cache is not explicitly configured via {@link #setAuthenticationCache(org.apache.shiro.cache.Cache)}.
     * <p/>
     * This name will only be used to look up a cache if authentication caching is
     * {@link #isAuthenticationCachingEnabled() enabled}.
     * <p/>
     * <b>WARNING:</b> Only set this property if safe caching conditions apply, as documented at the top
     * of this page in the class-level JavaDoc.
     *
     * @return the name of a {@link Cache} to lookup from any available {@link #getCacheManager() cacheManager} if
     * a cache is not explicitly configured via {@link #setAuthenticationCache(org.apache.shiro.cache.Cache)}.
     * @see #isAuthenticationCachingEnabled()
     */
    public String getAuthenticationCacheName() {
        return authenticationCacheName;
    }

    /**
     * Sets the name of a {@link Cache} to lookup from any available {@link #getCacheManager() cacheManager} if
     * a cache is not explicitly configured via {@link #setAuthenticationCache(org.apache.shiro.cache.Cache)}.
     * <p/>
     * This name will only be used to look up a cache if authentication caching is
     * {@link #isAuthenticationCachingEnabled() enabled}.
     *
     * @param authenticationCacheName the name of a {@link Cache} to lookup from any available
     *                                {@link #getCacheManager() cacheManager} if a cache is not explicitly configured
     *                                via {@link #setAuthenticationCache(org.apache.shiro.cache.Cache)}.
     * @see #isAuthenticationCachingEnabled()
     */
    public void setAuthenticationCacheName(String authenticationCacheName) {
        this.authenticationCacheName = authenticationCacheName;
    }

    /**
     * Returns {@code true} if authentication caching should be utilized if a {@link CacheManager} has been
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) configured}, {@code false} otherwise.
     * <p/>
     * The default value is {@code true}.
     *
     * @return {@code true} if authentication caching should be utilized, {@code false} otherwise.
     */
    public boolean isAuthenticationCachingEnabled() {
        return authenticationCachingEnabled && isCachingEnabled();
    }

    /**
     * Sets whether or not authentication caching should be utilized if a {@link CacheManager} has been
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) configured}, {@code false} otherwise.
     * <p/>
     * The default value is {@code false} to retain backwards compatibility with Shiro 1.1 and earlier.
     * <p/>
     * <b>WARNING:</b> Only set this property to {@code true} if safe caching conditions apply, as documented at the top
     * of this page in the class-level JavaDoc.
     *
     * @param authenticationCachingEnabled the value to set
     */
    @SuppressWarnings({"UnusedDeclaration"})
    public void setAuthenticationCachingEnabled(boolean authenticationCachingEnabled) {
        this.authenticationCachingEnabled = authenticationCachingEnabled;
        if (authenticationCachingEnabled) {
            setCachingEnabled(true);
        }
    }

    public void setName(String name) {
        // FIXME This is then no longer the cacheName Is it still used for the cacheName?
        String authcCacheName = authenticationCacheName;
        if (authcCacheName != null && authcCacheName.startsWith(getClass().getName())) {
            //get rid of the default heuristically-created cache name.  Create a more meaningful one
            //based on the application-unique Realm name:
            authenticationCacheName = name + DEFAULT_AUTHORIZATION_CACHE_SUFFIX;
        }
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * Convenience implementation that returns
     * <tt>getAuthenticationTokenClass().isAssignableFrom( token.getClass() );</tt>.  Can be overridden
     * by subclasses for more complex token checking.
     * <p>Most configurations will only need to set a different class via
     * {@link #setAuthenticationTokenClass}, as opposed to overriding this method.
     *
     * @param token the token being submitted for authentication.
     * @return true if this authentication realm can process the submitted token instance of the class, false otherwise.
     */
    public boolean supports(AuthenticationToken token) {
        throw new UnsupportedOperationException("TODO be.rubus.jsr375.octopus.realm.AuthenticatingRealm.supports");
        //return token != null && getAuthenticationTokenClass().isAssignableFrom(token.getClass());
    }

    /**
     * Initializes this realm and potentially enables an authentication cache, depending on configuration.  Based on
     * the availability of an authentication cache, this class functions as follows:
     * <ol>
     * <li>If the {@link #setAuthenticationCache cache} property has been set, it will be
     * used to cache the AuthenticationInfo objects returned from {@link #getAuthenticationInfo}
     * method invocations.
     * All future calls to {@link #getAuthenticationInfo} will attempt to use this cache first
     * to alleviate any potentially unnecessary calls to an underlying data store.</li>
     * <li>If the {@link #setAuthenticationCache cache} property has <b>not</b> been set,
     * the {@link #setCacheManager cacheManager} property will be checked.
     * If a {@code cacheManager} has been set, it will be used to eagerly acquire an authentication
     * {@code cache}, and this cache which will be used as specified in #1.</li>
     * <li>If neither the {@link #setAuthenticationCache (org.apache.shiro.cache.Cache) authenticationCache}
     * or {@link #setCacheManager(org.apache.shiro.cache.CacheManager) cacheManager}
     * properties are set, caching will not be utilized and authentication look-ups will be delegated to
     * subclass implementations for each authentication attempt.</li>
     * </ol>
     * <p/>
     * This method finishes by calling {@link #onInit()} is to allow subclasses to perform any init behavior desired.
     */
    @PostConstruct
    public void init() {
        //trigger obtaining the authorization cache if possible
        getAvailableAuthenticationCache();
        onInit();
    }

    /**
     * Template method for subclasses to implement any initialization logic.  Called from
     * {@link #init()}.
     */
    protected void onInit() {
    }

    /**
     * This implementation attempts to acquire an authentication cache if one is not already configured.
     */
    protected void afterCacheManagerSet() {
        //trigger obtaining the authorization cache if possible
        getAvailableAuthenticationCache();
    }

    /**
     * Returns any available {@link Cache} instance to use for authentication caching.  This functions as follows:
     * <ol>
     * <li>If an {@link #setAuthenticationCache(org.apache.shiro.cache.Cache) authenticationCache} has been explicitly
     * configured (it is not null), it is returned.</li>
     * <li>If there is no {@link #getAuthenticationCache() authenticationCache} configured:
     * <ol>
     * <li>If authentication caching is {@link #isAuthenticationCachingEnabled() enabled}, any available
     * {@link #getCacheManager() cacheManager} will be consulted to obtain an available authentication cache.
     * </li>
     * <li>If authentication caching is disabled, this implementation does nothing.</li>
     * </ol>
     * </li>
     * </ol>
     *
     * @return any available {@link Cache} instance to use for authentication caching.
     */
    private Cache<Object, AuthenticationInfo> getAvailableAuthenticationCache() {
        Cache<Object, AuthenticationInfo> cache = getAuthenticationCache();
        boolean authcCachingEnabled = isAuthenticationCachingEnabled();
        if (cache == null && authcCachingEnabled) {
            cache = getAuthenticationCacheLazy();
        }
        return cache;
    }

    /**
     * Checks to see if the authenticationCache class attribute is null, and if so, attempts to acquire one from
     * any configured {@link #getCacheManager() cacheManager}.  If one is acquired, it is set as the class attribute.
     * The class attribute is then returned.
     *
     * @return an available cache instance to be used for authentication caching or {@code null} if one is not available.
     */
    private Cache<Object, AuthenticationInfo> getAuthenticationCacheLazy() {

        if (authenticationCache == null) {

            log.trace("No authenticationCache instance set.  Checking for a cacheManager...");

            CacheManager cacheManager = getCacheManager();

            if (cacheManager != null) {
                String cacheName = getAuthenticationCacheName();
                log.debug("CacheManager [{}] configured.  Building authentication cache '{}'", cacheManager, cacheName);
                authenticationCache = cacheManager.getCache(cacheName);
            }
        }

        return authenticationCache;
    }

    /**
     * Returns any cached AuthenticationInfo corresponding to the specified token or {@code null} if there currently
     * isn't any cached data.
     *
     * @param token the token submitted during the authentication attempt.
     * @return any cached AuthenticationInfo corresponding to the specified token or {@code null} if there currently
     * isn't any cached data.
     */
    private AuthenticationInfo getCachedAuthenticationInfo(AuthenticationToken token) {
        AuthenticationInfo info = null;

        Cache<Object, AuthenticationInfo> cache = getAvailableAuthenticationCache();
        if (cache != null && token != null) {
            log.trace("Attempting to retrieve the AuthenticationInfo from cache.");
            Object key = getAuthenticationCacheKey(token);
            info = cache.get(key);
            if (info == null) {
                log.trace("No AuthorizationInfo found in cache for key [{}]", key);
            } else {
                log.trace("Found cached AuthorizationInfo for key [{}]", key);
            }
        }

        return info;
    }

    /**
     * Caches the specified info if authentication caching
     * {@link #isAuthenticationCachingEnabled(org.apache.shiro.authc.AuthenticationToken, org.apache.shiro.authc.AuthenticationInfo) isEnabled}
     * for the specific token/info pair and a cache instance is available to be used.
     *
     * @param token the authentication token submitted which resulted in a successful authentication attempt.
     * @param info  the AuthenticationInfo to cache as a result of the successful authentication attempt.
     */
    private void cacheAuthenticationInfoIfPossible(AuthenticationToken token, AuthenticationInfo info) {
        if (!isAuthenticationCachingEnabled(token, info)) {
            log.debug("AuthenticationInfo caching is disabled for info [{}].  Submitted token: [{}].", info, token);
            //return quietly, caching is disabled for this token/info pair:
            return;
        }

        Cache<Object, AuthenticationInfo> cache = getAvailableAuthenticationCache();
        if (cache != null) {
            Object key = getAuthenticationCacheKey(token);
            cache.put(key, info);
            log.trace("Cached AuthenticationInfo for continued authentication.  key=[{}], value=[{}].", key, info);
        }
    }

    /**
     * Returns {@code true} if authentication caching should be utilized based on the specified
     * {@link AuthenticationToken} and/or {@link AuthenticationInfo}, {@code false} otherwise.
     * <p/>
     * The default implementation simply delegates to {@link #isAuthenticationCachingEnabled()}, the general-case
     * authentication caching setting.  Subclasses can override this to turn on or off caching at runtime
     * based on the specific submitted runtime values.
     *
     * @param token the submitted authentication token
     * @param info  the {@code AuthenticationInfo} acquired from data source lookup via
     *              {@link #doGetAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken)}
     * @return {@code true} if authentication caching should be utilized based on the specified
     * {@link AuthenticationToken} and/or {@link AuthenticationInfo}, {@code false} otherwise.
     */
    protected boolean isAuthenticationCachingEnabled(AuthenticationToken token, AuthenticationInfo info) {
        return isAuthenticationCachingEnabled();
    }

    /**
     * This implementation functions as follows:
     * <ol>
     * <li>It attempts to acquire any cached {@link AuthenticationInfo} corresponding to the specified
     * {@link AuthenticationToken} argument.  If a cached value is found, it will be used for credentials matching,
     * alleviating the need to perform any lookups with a data source.</li>
     * <li>If there is no cached {@link AuthenticationInfo} found, delegate to the
     * {@link #doGetAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken)} method to perform the actual
     * lookup.  If authentication caching is enabled and possible, any returned info object will be
     * {@link #cacheAuthenticationInfoIfPossible(org.apache.shiro.authc.AuthenticationToken, org.apache.shiro.authc.AuthenticationInfo) cached}
     * to be used in future authentication attempts.</li>
     * <li>If an AuthenticationInfo instance is not found in the cache or by lookup, {@code null} is returned to
     * indicate an account cannot be found.</li>
     * <li>If an AuthenticationInfo instance is found (either cached or via lookup), ensure the submitted
     * AuthenticationToken's credentials match the expected {@code AuthenticationInfo}'s credentials using the
     * {@link #getCredentialsMatcher() credentialsMatcher}.  This means that credentials are always verified
     * for an authentication attempt.</li>
     * </ol>
     *
     * @param token the submitted account principal and credentials.
     * @return the AuthenticationInfo corresponding to the given {@code token}, or {@code null} if no
     * AuthenticationInfo could be found.
     * @throws AuthenticationException if authentication failed.
     */
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        AuthenticationInfo info = getCachedAuthenticationInfo(token);
        if (info == null) {
            //otherwise not cached, perform the lookup:
            info = doGetAuthenticationInfo(token);
            log.debug("Looked up AuthenticationInfo [{}] from doGetAuthenticationInfo", info);
            if (token != null && info != null) {
                cacheAuthenticationInfoIfPossible(token, info);
            }
        } else {
            log.debug("Using cached authentication info [{}] to perform credentials matching.", info);
        }

        if (info != null) {
            assertCredentialsMatch(token, info);
        } else {
            log.debug("No AuthenticationInfo found for submitted AuthenticationToken [{}].  Returning null.", token);
        }

        return info;
    }

    /**
     * Asserts that the submitted {@code AuthenticationToken}'s credentials match the stored account
     * {@code AuthenticationInfo}'s credentials, and if not, throws an {@link AuthenticationException}.
     *
     * @param token the submitted authentication token
     * @param info  the AuthenticationInfo corresponding to the given {@code token}
     * @throws AuthenticationException if the token's credentials do not match the stored account credentials.
     */
    protected void assertCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) throws AuthenticationException {
        prepareCredentialsMatcherHandler();
        if (!credentialsMatcher.doCredentialsMatch(token, info)) {
            //not successful - throw an exception to indicate this:
            String msg = "Submitted credentials for token [" + token + "] did not match the expected credentials.";
            throw new IncorrectCredentialsException(msg);
        }

    }

    private void prepareCredentialsMatcherHandler() {
        credentialsMatcher = new CredentialsMatcherHandler();
    }

    /**
     * Returns the key under which {@link AuthenticationInfo} instances are cached if authentication caching is enabled.
     * This implementation defaults to returning the token's
     * {@link org.apache.shiro.authc.AuthenticationToken#getPrincipal() principal}, which is usually a username in
     * most applications.
     * <h3>Cache Invalidation on Logout</h3>
     * <b>NOTE:</b> If you want to be able to invalidate an account's cached {@code AuthenticationInfo} on logout, you
     * must ensure the {@link #getAuthenticationCacheKey(org.apache.shiro.subject.PrincipalCollection)} method returns
     * the same value as this method.
     *
     * @param token the authentication token for which any successful authentication will be cached.
     * @return the cache key to use to cache the associated {@link AuthenticationInfo} after a successful authentication.
     */
    protected Object getAuthenticationCacheKey(AuthenticationToken token) {
        return token != null ? token.getPrincipal() : null;
    }

    /**
     * Returns the key under which {@link AuthenticationInfo} instances are cached if authentication caching is enabled.
     * This implementation delegates to
     * {@link #getAvailablePrincipal(org.apache.shiro.subject.PrincipalCollection)}, which returns the primary principal
     * associated with this particular Realm.
     * <h3>Cache Invalidation on Logout</h3>
     * <b>NOTE:</b> If you want to be able to invalidate an account's cached {@code AuthenticationInfo} on logout, you
     * must ensure that this method returns the same value as the
     * {@link #getAuthenticationCacheKey(org.apache.shiro.authc.AuthenticationToken)} method!
     *
     * @param principals the principals of the account for which to set or remove cached {@code AuthenticationInfo}.
     * @return the cache key to use when looking up cached {@link AuthenticationInfo} instances.
     */
    protected Object getAuthenticationCacheKey(PrincipalCollection principals) {
        return getAvailablePrincipal(principals);
    }

    /**
     * This implementation clears out any cached authentication data by calling
     * {@link #clearCachedAuthenticationInfo(org.apache.shiro.subject.PrincipalCollection)}.
     * If overriding in a subclass, be sure to call {@code super.doClearCache} to ensure this behavior is maintained.
     *
     * @param principals principals the principals of the account for which to clear any cached data.
     */
    @Override
    protected void doClearCache(PrincipalCollection principals) {
        super.doClearCache(principals);
        clearCachedAuthenticationInfo(principals);
    }

    /**
     * Clears out the AuthenticationInfo cache entry for the specified account.
     * <p/>
     * This method is provided as a convenience to subclasses so they can invalidate a cache entry when they
     * change an account's authentication data (e.g. reset password) during runtime.  Because an account's
     * AuthenticationInfo can be cached, there needs to be a way to invalidate the cache for only that account so that
     * subsequent authentication operations don't used the (old) cached value if account data changes.
     * <p/>
     * After this method is called, the next authentication for that same account will result in a call to
     * {@link #doGetAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken) doGetAuthenticationInfo}, and the
     * resulting return value will be cached before being returned so it can be reused for later authentications.
     * <p/>
     * If you wish to clear out all associated cached data (and not just authentication data), use the
     * {@link #clearCache(org.apache.shiro.subject.PrincipalCollection)} method instead (which will in turn call this
     * method by default).
     *
     * @param principals the principals of the account for which to clear the cached AuthorizationInfo.
     * @see #clearCache(org.apache.shiro.subject.PrincipalCollection)
     */
    protected void clearCachedAuthenticationInfo(PrincipalCollection principals) {
        if (!CollectionUtils.isEmpty(principals)) {
            Cache<Object, AuthenticationInfo> cache = getAvailableAuthenticationCache();
            //cache instance will be non-null if caching is enabled:
            if (cache != null) {
                Object key = getAuthenticationCacheKey(principals);
                cache.remove(key);
            }
        }
    }

    /**
     * Retrieves authentication data from an implementation-specific datasource (RDBMS, LDAP, etc) for the given
     * authentication token.
     * <p/>
     * For most datasources, this means just 'pulling' authentication data for an associated subject/user and nothing
     * more and letting Shiro do the rest.  But in some systems, this method could actually perform EIS specific
     * log-in logic in addition to just retrieving data - it is up to the Realm implementation.
     * <p/>
     * A {@code null} return value means that no account could be associated with the specified token.
     *
     * @param token the authentication token containing the user's principal and credentials.
     * @return an {@link AuthenticationInfo} object containing account data resulting from the
     * authentication ONLY if the lookup is successful (i.e. account exists and is valid, etc.)
     * @throws AuthenticationException if there is an error acquiring data or performing
     *                                 realm-specific authentication logic for the specified <tt>token</tt>
     */
    protected abstract AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException;

}