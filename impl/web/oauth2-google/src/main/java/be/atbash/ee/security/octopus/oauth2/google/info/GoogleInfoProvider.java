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
package be.atbash.ee.security.octopus.oauth2.google.info;

import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import be.atbash.ee.security.octopus.oauth2.google.GoogleProvider;
import be.atbash.ee.security.octopus.oauth2.google.json.GoogleJSONProcessor;
import be.atbash.ee.security.octopus.oauth2.google.provider.GoogleOAuth2ServiceProducer;
import be.atbash.ee.security.octopus.oauth2.info.OAuth2InfoProvider;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

/**
 *
 */
@ApplicationScoped
@GoogleProvider
public class GoogleInfoProvider implements OAuth2InfoProvider {

    @Inject
    private GoogleOAuth2ServiceProducer googleOAuth2ServiceProducer;

    @Inject
    private GoogleJSONProcessor jsonProcessor;

    @Override
    public OAuth2UserToken retrieveUserInfo(OAuth2AccessToken token, HttpServletRequest servletRequest) {

        // No state here so token can be null.
        OAuth20Service authService = googleOAuth2ServiceProducer.createOAuthService(servletRequest, null);
        OAuthRequest request = new OAuthRequest(Verb.GET, "https://www.googleapis.com/oauth2/v3/userinfo");

        authService.signRequest(token, request);
        OAuth2UserToken googleUserToken;
        try {
            Response oResp = authService.execute(request);
            googleUserToken = jsonProcessor.extractGoogleUser(oResp.getBody());
            googleUserToken.setToken(token);
        } catch (InterruptedException | ExecutionException | IOException e) {
            throw new AtbashUnexpectedException(e);
        }

        // Offline -> revoke token? https://accounts.google.com/o/oauth2/revoke?token={token}
        return googleUserToken;

    }
}
