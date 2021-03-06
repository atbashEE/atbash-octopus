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
import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.UnauthorizedException;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.PermissionAdapter;
import be.atbash.ee.security.octopus.authz.permission.PermissionResolver;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermissionResolver;
import be.atbash.ee.security.octopus.cache.Cache;
import be.atbash.ee.security.octopus.cache.CacheManager;
import be.atbash.ee.security.octopus.realm.mgmt.LookupProvider;
import be.atbash.ee.security.octopus.realm.mgmt.RoleMapperProvider;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.CDIUtils;
import be.atbash.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * An {@code AuthorizingRealm} extends the {@code AuthenticatingRealm}'s capabilities by adding Authorization
 * (access control) support.
 * <p/>
 * This implementation will perform all role and permission checks automatically (and subclasses do not have to
 * write this logic) as long as the
 * {@link #getAuthorizationInfo(PrincipalCollection)} method returns an
 * {@link AuthorizationInfo}.  Please see that method's JavaDoc for an in-depth explanation.
 * <p/>
 * If you find that you do not want to utilize the {@link AuthorizationInfo AuthorizationInfo} construct,
 * you are of course free to subclass the {@link AuthenticatingRealm AuthenticatingRealm} directly instead and
 * implement the remaining Realm interface methods directly.  You might do this if you want have better control
 * over how the Role and Permission checks occur for your specific data source.  However, using AuthorizationInfo
 * (and its default implementation {@link be.atbash.ee.security.octopus.authz.SimpleAuthorizationInfo SimpleAuthorizationInfo}) is sufficient in the large
 * majority of Realm cases.
 *
 * @see be.atbash.ee.security.octopus.authz.SimpleAuthorizationInfo
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.realm.AuthorizingRealm"})
public abstract class AuthorizingRealm extends AuthenticatingRealm {

    //TODO - complete JavaDoc

    /*-------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final Logger log = LoggerFactory.getLogger(AuthorizingRealm.class);

    /**
     * The default suffix appended to the realm name for caching AuthorizationInfo instances.
     */
    private static final String DEFAULT_AUTHORIZATION_CACHE_SUFFIX = ".authorizationCache";

    private static final AtomicInteger INSTANCE_COUNT = new AtomicInteger();

    /*-------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The cache used by this realm to store AuthorizationInfo instances associated with individual Subject principals.
     */
    private boolean authorizationCachingEnabled;
    private Cache<Object, AuthorizationInfo> authorizationCache;
    private String authorizationCacheName;

    @Inject
    private PermissionResolver permissionResolver;

    private RolePermissionResolver rolePermissionResolver;
    private PermissionAdapter permissionAdapter;

    /*-------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    public AuthorizingRealm() {
        // Keep this initialization here (and not within PostConstruct) as it is also used in Java SE)
        // But this is then executed multiple times when OctopusRealm is created (just as expected with CDI)
        authorizationCachingEnabled = true; // FIXME Fom config retrieve if cache is enabled or not.

        int instanceNumber = INSTANCE_COUNT.getAndIncrement();
        authorizationCacheName = getClass().getName() + DEFAULT_AUTHORIZATION_CACHE_SUFFIX;
        if (instanceNumber > 0) {
            authorizationCacheName = authorizationCacheName + "." + instanceNumber;
        }
    }

    @PostConstruct
    public void init() {
        super.init();
        rolePermissionResolver = CDIUtils.retrieveOptionalInstance(RolePermissionResolver.class);
        permissionAdapter = CDIUtils.retrieveOptionalInstance(PermissionAdapter.class);
    }

    /**
     * Used in the Java SE case.
     *
     * @param <T>
     * @param lookupProvider
     * @param roleMapperProvider
     */
    <T extends Enum<T>> void initDependencies(LookupProvider<T> lookupProvider, RoleMapperProvider roleMapperProvider) {
        permissionResolver = new PermissionResolver(lookupProvider.getPermissionLookup(), lookupProvider.getStringPermissionLookup());

        rolePermissionResolver = roleMapperProvider.getRolePermissionResolver();
        // FIXME
        //permissionAdapter =

        super.init();
    }

    /*-------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public void setName(String name) {
        super.setName(name);
        String authzCacheName = this.authorizationCacheName;
        if (authzCacheName != null && authzCacheName.startsWith(getClass().getName())) {
            //get rid of the default class-name based cache name.  Create a more meaningful one
            //based on the application-unique Realm name:
            authorizationCacheName = name + DEFAULT_AUTHORIZATION_CACHE_SUFFIX;
        }
    }

    public Cache<Object, AuthorizationInfo> getAuthorizationCache() {
        return authorizationCache;
    }

    public String getAuthorizationCacheName() {
        return authorizationCacheName;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setAuthorizationCacheName(String authorizationCacheName) {
        this.authorizationCacheName = authorizationCacheName;
    }

    /**
     * Returns {@code true} if authorization caching should be utilized if a {@link CacheManager} has been
     * {@link #setCacheManager(CacheManager) configured}, {@code false} otherwise.
     * <p/>
     * The default value is {@code true}.
     *
     * @return {@code true} if authorization caching should be utilized, {@code false} otherwise.
     */
    public boolean isAuthorizationCachingEnabled() {
        return isCachingEnabled() && authorizationCachingEnabled;
    }

    /**
     * Sets whether or not authorization caching should be utilized if a {@link CacheManager} has been
     * {@link #setCacheManager(CacheManager) configured}, {@code false} otherwise.
     * <p/>
     * The default value is {@code true}.
     *
     * @param authenticationCachingEnabled the value to set
     */
    @SuppressWarnings({"UnusedDeclaration"})
    public void setAuthorizationCachingEnabled(boolean authenticationCachingEnabled) {
        this.authorizationCachingEnabled = authenticationCachingEnabled;
        if (authenticationCachingEnabled) {
            setCachingEnabled(true);
        }
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * Initializes this realm and potentially enables a cache, depending on configuration.
     * <p/>
     * When this method is called, the following logic is executed:
     * <ol>
     * <li>If the {@link #setAuthorizationCache cache} property has been set, it will be
     * used to cache the AuthorizationInfo objects returned from {@link #getAuthorizationInfo}
     * method invocations.
     * All future calls to {@code getAuthorizationInfo} will attempt to use this cache first
     * to alleviate any potentially unnecessary calls to an underlying data store.</li>
     * <li>If the {@link #setAuthorizationCache cache} property has <b>not</b> been set,
     * the {@link #setCacheManager cacheManager} property will be checked.
     * If a {@code cacheManager} has been set, it will be used to create an authorization
     * {@code cache}, and this newly created cache which will be used as specified in #1.</li>
     * <li>If neither the {@link #setAuthorizationCache (Cache) cache}
     * or {@link #setCacheManager(CacheManager) cacheManager}
     * properties are set, caching will be disabled and authorization look-ups will be delegated to
     * subclass implementations for each authorization check.</li>
     * </ol>
     */
    protected void onInit() {
        super.onInit();
        //trigger obtaining the authorization cache if possible
        getAvailableAuthorizationCache();
    }

    protected void afterCacheManagerSet() {
        super.afterCacheManagerSet();
        //trigger obtaining the authorization cache if possible
        getAvailableAuthorizationCache();
    }

    private Cache<Object, AuthorizationInfo> getAuthorizationCacheLazy() {

        if (authorizationCache == null) {

            if (log.isDebugEnabled()) {
                log.debug("No authorizationCache instance set.  Checking for a cacheManager...");
            }

            CacheManager cacheManager = getCacheManager();

            if (cacheManager != null) {
                String cacheName = getAuthorizationCacheName();
                if (log.isDebugEnabled()) {
                    log.debug("CacheManager [" + cacheManager + "] has been configured.  Building " +
                            "authorization cache named [" + cacheName + "]");
                }
                authorizationCache = cacheManager.getCache(cacheName);
            } else {
                if (log.isInfoEnabled()) {
                    log.info("No cache or cacheManager properties have been set.  Authorization cache cannot " +
                            "be obtained.");
                }
            }
        }

        return authorizationCache;
    }

    private Cache<Object, AuthorizationInfo> getAvailableAuthorizationCache() {
        Cache<Object, AuthorizationInfo> cache = getAuthorizationCache();
        if (cache == null && isAuthorizationCachingEnabled()) {
            cache = getAuthorizationCacheLazy();
        }
        return cache;
    }

    /**
     * Returns an account's authorization-specific information for the specified {@code principals},
     * or {@code null} if no account could be found.  The resulting {@code AuthorizationInfo} object is used
     * by the other method implementations in this class to automatically perform access control checks for the
     * corresponding {@code Subject}.
     * <p/>
     * This implementation obtains the actual {@code AuthorizationInfo} object from the subclass's
     * implementation of
     * {@link #doGetAuthorizationInfo(PrincipalCollection) doGetAuthorizationInfo}, and then
     * caches it for efficient reuse if caching is enabled (see below).
     * <p/>
     * Invocations of this method should be thought of as completely orthogonal to acquiring
     * {@link #getAuthenticationInfo(be.atbash.ee.security.octopus.token.AuthenticationToken) authenticationInfo}, since either could
     * occur in any order.
     * <p/>
     * For example, in &quot;Remember Me&quot; scenarios, the user identity is remembered (and
     * assumed) for their current session and an authentication attempt during that session might never occur.
     * But because their identity would be remembered, that is sufficient enough information to call this method to
     * execute any necessary authorization checks.  For this reason, authentication and authorization should be
     * loosely coupled and not depend on each other.
     * <h3>Caching</h3>
     * The {@code AuthorizationInfo} values returned from this method are cached for efficient reuse
     * if caching is enabled.  Caching is enabled automatically when an {@link #setAuthorizationCache authorizationCache}
     * instance has been explicitly configured, or if a {@link #setCacheManager cacheManager} has been configured, which
     * will be used to lazily create the {@code authorizationCache} as needed.
     * <p/>
     * If caching is enabled, the authorization cache will be checked first and if found, will return the cached
     * {@code AuthorizationInfo} immediately.  If caching is disabled, or there is a cache miss, the authorization
     * info will be looked up from the underlying data store via the
     * {@link #doGetAuthorizationInfo(PrincipalCollection)} method, which must be implemented
     * by subclasses.
     * <h4>Changed Data</h4>
     * If caching is enabled and if any authorization data for an account is changed at
     * runtime, such as adding or removing roles and/or permissions, the subclass implementation should clear the
     * cached AuthorizationInfo for that account via the
     * {@link #clearCachedAuthorizationInfo(PrincipalCollection) clearCachedAuthorizationInfo}
     * method.  This ensures that the next call to {@code getAuthorizationInfo(PrincipalCollection)} will
     * acquire the account's fresh authorization data, where it will then be cached for efficient reuse.  This
     * ensures that stale authorization data will not be reused.
     *
     * @param principals the corresponding Subject's identifying principals with which to look up the Subject's
     *                   {@code AuthorizationInfo}.
     * @return the authorization information for the account associated with the specified {@code principals},
     * or {@code null} if no account could be found.
     */
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        if (principals == null) {
            return null;
        }

        AuthorizationInfo info = null;

        if (log.isTraceEnabled()) {
            log.trace("Retrieving AuthorizationInfo for principals [" + principals + "]");
        }

        Cache<Object, AuthorizationInfo> cache = getAvailableAuthorizationCache();
        if (cache != null) {
            if (log.isTraceEnabled()) {
                log.trace("Attempting to retrieve the AuthorizationInfo from cache.");
            }
            Object key = getAuthorizationCacheKey(principals);
            info = cache.get(key);
            if (log.isTraceEnabled()) {
                if (info == null) {
                    log.trace("No AuthorizationInfo found in cache for principals [" + principals + "]");
                } else {
                    log.trace("AuthorizationInfo found in cache for principals [" + principals + "]");
                }
            }
        }

        if (info == null) {
            // Call template method if the info was not found in a cache
            info = doGetAuthorizationInfo(principals);
            cacheAuthorizationInfo(principals, info);
        }

        return info;
    }

    protected void cacheAuthorizationInfo(PrincipalCollection principals, AuthorizationInfo info) {
        // If the info is not null and the cache has been created, then cache the authorization info.
        Cache<Object, AuthorizationInfo> cache = getAvailableAuthorizationCache();
        if (info != null && cache != null) {
            if (log.isTraceEnabled()) {
                log.trace("Caching authorization info for principals: [" + principals + "].");
            }
            Object key = getAuthorizationCacheKey(principals);
            cache.put(key, info);
        }
    }

    public Collection<Permission> getMatchingPermissions(Subject subject, Permission permission) {
        // TODO Need some cache !!! (when !coreConfiguration.isDynamicAuthorization)
        Collection<Permission> result = new ArrayList<>();

        PrincipalCollection principals = subject.getPrincipals();
        AuthorizationInfo info = getAuthorizationInfo(principals);
        Collection<Permission> permissions = getPermissions(info, principals);

        for (Permission currentPermission : permissions) {
            if (currentPermission.implies(permission)) {
                result.add(currentPermission);
            }
        }
        return result;
    }

    public Collection<Permission> getPermissions(Subject subject) {
        // TODO Need some cache !!! (when !coreConfiguration.isDynamicAuthorization)
        PrincipalCollection principals = subject.getPrincipals();
        AuthorizationInfo info = getAuthorizationInfo(principals);

        return getPermissions(info, principals);
    }

    protected Object getAuthorizationCacheKey(PrincipalCollection principals) {
        return principals;
    }

    /**
     * Clears out the AuthorizationInfo cache entry for the specified account.
     * <p/>
     * This method is provided as a convenience to subclasses so they can invalidate a cache entry when they
     * change an account's authorization data (add/remove roles or permissions) during runtime.  Because an account's
     * AuthorizationInfo can be cached, there needs to be a way to invalidate the cache for only that account so that
     * subsequent authorization operations don't used the (old) cached value if account data changes.
     * <p/>
     * After this method is called, the next authorization check for that same account will result in a call to
     * {@link #getAuthorizationInfo(PrincipalCollection) getAuthorizationInfo}, and the
     * resulting return value will be cached before being returned so it can be reused for later authorization checks.
     * <p/>
     * If you wish to clear out all associated cached data (and not just authorization data), use the
     * {@link #clearCache(PrincipalCollection)} method instead (which will in turn call this
     * method by default).
     *
     * @param principals the principals of the account for which to clear the cached AuthorizationInfo.
     */
    protected void clearCachedAuthorizationInfo(PrincipalCollection principals) {
        if (principals == null) {
            return;
        }

        Cache<Object, AuthorizationInfo> cache = getAvailableAuthorizationCache();
        //cache instance will be non-null if caching is enabled:
        if (cache != null) {
            Object key = getAuthorizationCacheKey(principals);
            cache.remove(key);
        }
    }

    /**
     * Retrieves the AuthorizationInfo for the given principals from the underlying data store.  When returning
     * an instance from this method, you might want to consider using an instance of
     * {@link be.atbash.ee.security.octopus.authz.SimpleAuthorizationInfo SimpleAuthorizationInfo}, as it is suitable in most cases.
     *
     * @param principals the primary identifying principals of the AuthorizationInfo that should be retrieved.
     * @return the AuthorizationInfo associated with this principals.
     * @see be.atbash.ee.security.octopus.authz.SimpleAuthorizationInfo
     */
    protected abstract AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals);

    private Collection<Permission> getPermissions(AuthorizationInfo info, PrincipalCollection principals) {
        Set<Permission> permissions = new HashSet<>();

        if (info != null) {
            Collection<Permission> perms = info.getObjectPermissions();
            if (!CollectionUtils.isEmpty(perms)) {
                permissions.addAll(perms);
            }
            perms = resolvePermissions(info.getStringPermissions());
            if (!CollectionUtils.isEmpty(perms)) {
                permissions.addAll(perms);
            }

            perms = resolveRolePermissions(info.getRoles());
            if (!CollectionUtils.isEmpty(perms)) {
                permissions.addAll(perms);
            }
        }

        if (configuration.isDynamicAuthorization()) {
            permissions = permissionAdapter.adjustPermissions(permissions, principals);
        }
        if (permissions.isEmpty()) {
            return Collections.emptySet();
        } else {
            return Collections.unmodifiableSet(permissions);
        }
    }

    private Collection<Permission> resolvePermissions(Collection<String> stringPerms) {
        // FIXME, There should never be some String permissions left. They are converted already by the AuthorizationInfoBuilder
        Collection<Permission> perms = Collections.emptySet();

        if (!CollectionUtils.isEmpty(stringPerms)) {
            perms = new LinkedHashSet<>(stringPerms.size());
            for (String strPermission : stringPerms) {
                Permission permission = permissionResolver.resolvePermission(strPermission);
                perms.add(permission);
            }
        }

        return perms;

    }

    private Collection<Permission> resolveRolePermissions(Collection<String> roleNames) {
        Collection<Permission> perms = Collections.emptySet();

        if (!configuration.isDynamicAuthorization()) {
            // If the permissions/roles are handled static, the AuthorizationInfoBuilder has already made the conversion.
            return perms;
        }
        // FIXME This is also done in AuthenticationInfoBuilder?!
        if (rolePermissionResolver != null && !CollectionUtils.isEmpty(roleNames)) {
            perms = new LinkedHashSet<>(roleNames.size());
            for (String roleName : roleNames) {
                Collection<Permission> resolved = rolePermissionResolver.resolvePermissionsInRole(roleName);
                if (!CollectionUtils.isEmpty(resolved)) {
                    perms.addAll(resolved);
                }
            }
        }
        return perms;
    }

    public boolean isPermitted(PrincipalCollection principals, String permission) {
        Permission p = permissionResolver.resolvePermission(permission);
        return isPermitted(principals, p);

    }

    public boolean isPermitted(PrincipalCollection principals, Permission permission) {
        AuthorizationInfo info = getAuthorizationInfo(principals);
        return isPermitted(permission, info, principals);
    }

    private boolean isPermitted(Permission permission, AuthorizationInfo info, PrincipalCollection principals) {
        Collection<Permission> perms = getPermissions(info, principals);
        if (perms != null && !perms.isEmpty()) {
            for (Permission perm : perms) {
                if (perm.implies(permission)) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean[] isPermitted(PrincipalCollection subjectIdentifier, String... permissions) {
        List<Permission> perms = new ArrayList<>(permissions.length);
        throw new UnsupportedOperationException("not implemented be.atbash.ee.security.octopus.realm.AuthorizingRealm.isPermitted");
        /*
        for (String permString : permissions) {
            perms.add(getPermissionResolver().resolvePermission(permString));
        }
        return isPermitted(subjectIdentifier, perms);
        */
    }

    public boolean[] isPermitted(PrincipalCollection principals, List<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo(principals);
        return isPermitted(permissions, info, principals);
    }

    protected boolean[] isPermitted(List<Permission> permissions, AuthorizationInfo info, PrincipalCollection principals) {
        // FIXME Is this really used
        boolean[] result;
        if (permissions != null && !permissions.isEmpty()) {
            int size = permissions.size();
            result = new boolean[size];
            int i = 0;
            for (Permission p : permissions) {
                result[i++] = isPermitted(p, info, principals);
            }
        } else {
            result = new boolean[0];
        }
        return result;
    }

    public boolean isPermittedAll(PrincipalCollection subjectIdentifier, String... permissions) {
        throw new UnsupportedOperationException("not implemented be.atbash.ee.security.octopus.realm.AuthorizingRealm.isPermittedAll");
        /*
        if (permissions != null && permissions.length > 0) {
            Collection<Permission> perms = new ArrayList<Permission>(permissions.length);
            for (String permString : permissions) {
                perms.add(getPermissionResolver().resolvePermission(permString));
            }
            return isPermittedAll(subjectIdentifier, perms);
        }
        return false;
        */
    }

    public boolean isPermittedAll(PrincipalCollection principals, Collection<Permission> permissions) {
        // FIXME is this really used??
        AuthorizationInfo info = getAuthorizationInfo(principals);
        return info != null && isPermittedAll(permissions, info, principals);
    }

    protected boolean isPermittedAll(Collection<Permission> permissions, AuthorizationInfo info, PrincipalCollection principals) {
        if (permissions != null && !permissions.isEmpty()) {
            for (Permission p : permissions) {
                if (!isPermitted(p, info, principals)) {
                    return false;
                }
            }
        }
        return true;
    }

    public void checkPermission(PrincipalCollection subjectIdentifier, String permission) throws AuthorizationException {
        Permission p = permissionResolver.resolvePermission(permission);
        checkPermission(subjectIdentifier, p);
    }

    public void checkPermission(PrincipalCollection principals, Permission permission) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo(principals);
        checkPermission(permission, info, principals);
    }

    protected void checkPermission(Permission permission, AuthorizationInfo info, PrincipalCollection principals) {
        if (!isPermitted(permission, info, principals)) {
            String msg = "User is not permitted [" + permission + "]";
            throw new UnauthorizedException(msg);
        }
    }

    public void checkPermissions(PrincipalCollection subjectIdentifier, String... permissions) throws AuthorizationException {
        if (permissions != null) {
            for (String permString : permissions) {
                checkPermission(subjectIdentifier, permString);
            }
        }
    }

    public void checkPermissions(PrincipalCollection principals, Collection<Permission> permissions) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo(principals);
        checkPermissions(permissions, info, principals);
    }

    protected void checkPermissions(Collection<Permission> permissions, AuthorizationInfo info, PrincipalCollection principals) {
        if (permissions != null && !permissions.isEmpty()) {
            for (Permission p : permissions) {
                checkPermission(p, info, principals);
            }
        }
    }

    public boolean hasRole(PrincipalCollection principal, String roleIdentifier) {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        return hasRole(roleIdentifier, info);
    }

    protected boolean hasRole(String roleIdentifier, AuthorizationInfo info) {
        return info != null && info.getRoles() != null && info.getRoles().contains(roleIdentifier);
    }

    public boolean[] hasRoles(PrincipalCollection principal, List<String> roleIdentifiers) {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        boolean[] result = new boolean[roleIdentifiers != null ? roleIdentifiers.size() : 0];
        if (info != null) {
            result = hasRoles(roleIdentifiers, info);
        }
        return result;
    }

    protected boolean[] hasRoles(List<String> roleIdentifiers, AuthorizationInfo info) {
        boolean[] result;
        if (roleIdentifiers != null && !roleIdentifiers.isEmpty()) {
            int size = roleIdentifiers.size();
            result = new boolean[size];
            int i = 0;
            for (String roleName : roleIdentifiers) {
                result[i++] = hasRole(roleName, info);
            }
        } else {
            result = new boolean[0];
        }
        return result;
    }

    public boolean hasAllRoles(PrincipalCollection principal, Collection<String> roleIdentifiers) {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        return info != null && hasAllRoles(roleIdentifiers, info);
    }

    private boolean hasAllRoles(Collection<String> roleIdentifiers, AuthorizationInfo info) {
        if (roleIdentifiers != null && !roleIdentifiers.isEmpty()) {
            for (String roleName : roleIdentifiers) {
                if (!hasRole(roleName, info)) {
                    return false;
                }
            }
        }
        return true;
    }

    public void checkRole(PrincipalCollection principal, String role) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        checkRole(role, info);
    }

    protected void checkRole(String role, AuthorizationInfo info) {
        if (!hasRole(role, info)) {
            String msg = "User does not have role [" + role + "]";
            throw new UnauthorizedException(msg);
        }
    }

    public void checkRoles(PrincipalCollection principal, Collection<String> roles) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        checkRoles(roles, info);
    }

    public void checkRoles(PrincipalCollection principal, String... roles) throws AuthorizationException {
        checkRoles(principal, Arrays.asList(roles));
    }

    protected void checkRoles(Collection<String> roles, AuthorizationInfo info) {
        if (roles != null && !roles.isEmpty()) {
            for (String roleName : roles) {
                checkRole(roleName, info);
            }
        }
    }

    /**
     * Calls {@code super.doClearCache} to ensure any cached authentication data is removed and then calls
     * {@link #clearCachedAuthorizationInfo(PrincipalCollection)} to remove any cached
     * authorization data.
     * <p/>
     * If overriding in a subclass, be sure to call {@code super.doClearCache} to ensure this behavior is maintained.
     *
     * @param principals the principals of the account for which to clear any cached AuthorizationInfo
     */
    @Override
    protected void doClearCache(PrincipalCollection principals) {
        super.doClearCache(principals);
        clearCachedAuthorizationInfo(principals);
    }

}
