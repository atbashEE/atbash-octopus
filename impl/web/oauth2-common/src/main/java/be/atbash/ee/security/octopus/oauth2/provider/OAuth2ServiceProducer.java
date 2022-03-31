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
package be.atbash.ee.security.octopus.oauth2.provider;

import be.atbash.ee.security.octopus.util.URLUtil;
import com.github.scribejava.core.oauth.OAuth20Service;

import jakarta.enterprise.inject.Vetoed;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;

/**
 *
 */
@Vetoed
public abstract class OAuth2ServiceProducer {

    @Inject
    private URLUtil urlUtil;

    /**
     * @param req
     * @param csrfToken value for the state parameter, allowed to be null in case you don't need it
     * @return
     */
    public abstract OAuth20Service createOAuthService(HttpServletRequest req, String csrfToken);

    protected String assembleCallbackUrl(HttpServletRequest request) {
        // TODO Define config value for /oauth2callback
        return urlUtil.determineRoot(request) + "/oauth2callback";
    }

}
