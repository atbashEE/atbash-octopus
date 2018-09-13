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
package be.atbash.ee.security.octopus.oauth2.info;

import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import com.github.scribejava.core.model.OAuth2AccessToken;

import javax.servlet.http.HttpServletRequest;

/**
 * Hiding the retrieving user info from Oauth2 provider.
 */
public interface OAuth2InfoProvider {

    /**
     * Retrieve user token.
     *
     * @param token          AccessToken
     * @param servletRequest request during which OAuth2 authentication was initialized.
     * @return OAuth2UserToken with user info, never null (should throw exception)
     */
    OAuth2UserToken retrieveUserInfo(OAuth2AccessToken token, HttpServletRequest servletRequest);
}
