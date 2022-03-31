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
package be.atbash.ee.security.octopus.oauth2.filter.authc;

import be.atbash.ee.security.octopus.cache.Cache;
import be.atbash.ee.security.octopus.cache.CacheSupplier;
import be.atbash.ee.security.octopus.fake.LoginAuthenticationTokenProvider;
import be.atbash.ee.security.octopus.filter.RestAuthenticatingFilter;
import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import be.atbash.ee.security.octopus.oauth2.info.OAuth2InfoProvider;
import be.atbash.ee.security.octopus.realm.CachingRealm;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import com.github.scribejava.core.model.OAuth2AccessToken;

import jakarta.inject.Inject;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Date;


public abstract class AbstractOAuth2AuthenticatingFilter extends RestAuthenticatingFilter {

    @Inject
    private CacheSupplier cacheSupplier;

    @Override
    protected AuthenticationToken createToken(HttpServletRequest servletRequest, String token) {
        OAuth2UserToken oauth2Token = getCachedOAuth2User(token);

        if (oauth2Token == null) {
            oauth2Token = useFakeLogin(servletRequest, token);
        }

        if (oauth2Token == null) {
            // We don't have a cached version which is still valid.
            oauth2Token = getOAuth2User(servletRequest, token);


            if (oauth2Token != null) {
                oauth2Token.setToken(new OAuth2AccessToken(token));
                setCachedOAuth2User(token, oauth2Token);
            }

        }

        /*
        FIXME

        if (oauth2Token == null) {
            // FIXME Check If this status setting is required.
            ((HttpServletResponse) response).setStatus(401);
            return new IncorrectDataToken("Unable to create the Authentication token based on the request info");
        }
        */

        return oauth2Token;

    }

    private void setCachedOAuth2User(String authToken, OAuth2UserToken oauth2User) {
        Cache<String, CachedOAuth2User> cache = getCache();

        if (cache != null) {
            cache.put(authToken, new CachedOAuth2User(oauth2User));
        }
    }

    private OAuth2UserToken getOAuth2User(HttpServletRequest request, String authToken) {

        OAuth2AccessToken token = new OAuth2AccessToken(authToken);

        return getInfoProvider().retrieveUserInfo(token, request);

    }

    private OAuth2UserToken useFakeLogin(HttpServletRequest servletRequest, String authToken) {

        OAuth2UserToken result = null;

        LoginAuthenticationTokenProvider loginAuthenticationTokenProvider = getLoginAuthenticationTokenProvider();
        // TODO localhost only -> constant. Future -> more/multiple configurable hostnames
        if ("localhost".equals(servletRequest.getServerName()) && loginAuthenticationTokenProvider != null) {
            result = (OAuth2UserToken) loginAuthenticationTokenProvider.determineAuthenticationToken(authToken);
        }
        return result;
    }

    private OAuth2UserToken getCachedOAuth2User(String authToken) {
        OAuth2UserToken result = null;
        Cache<String, CachedOAuth2User> cache = getCache();

        if (cache != null) {
            CachedOAuth2User cachedOAuth2User = cache.get(authToken);
            if (cachedOAuth2User != null && cachedOAuth2User.isNotTimedOut()) {
                result = cachedOAuth2User.getOAuth2User();
            }
        }
        return result;
    }

    private Cache<String, CachedOAuth2User> getCache() {

        return cacheSupplier.retrieveCache(CachingRealm.CacheName.OAUTH2_TOKEN);

    }

    protected abstract OAuth2InfoProvider getInfoProvider();

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return executeLogin(request, response);
    }

    public static class CachedOAuth2User {
        private long creationTimeStamp;
        private OAuth2UserToken oAuth2User;

        public CachedOAuth2User(OAuth2UserToken oAuth2User) {
            this.oAuth2User = oAuth2User;
            creationTimeStamp = new Date().getTime();
        }

        boolean isNotTimedOut() {
            return (new Date().getTime() - creationTimeStamp) < 1800000; // 30 min
        }

        public OAuth2UserToken getOAuth2User() {
            return oAuth2User;
        }
    }

}