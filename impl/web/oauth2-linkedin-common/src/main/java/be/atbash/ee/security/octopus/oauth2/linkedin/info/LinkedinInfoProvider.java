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
package be.atbash.ee.security.octopus.oauth2.linkedin.info;

import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import be.atbash.ee.security.octopus.oauth2.info.OAuth2InfoProvider;
import be.atbash.ee.security.octopus.oauth2.linkedin.LinkedinProvider;
import be.atbash.ee.security.octopus.oauth2.linkedin.json.LinkedinJSONProcessor;
import be.atbash.ee.security.octopus.oauth2.linkedin.provider.LinkedinOAuth2ServiceProducer;
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
@LinkedinProvider
public class LinkedinInfoProvider implements OAuth2InfoProvider {

    @Inject
    private LinkedinOAuth2ServiceProducer linkedOAuth2ServiceProducer;

    @Inject
    private LinkedinJSONProcessor jsonProcessor;

    @Override
    public OAuth2UserToken retrieveUserInfo(OAuth2AccessToken token, HttpServletRequest req) {

        // No state here so token can be null.
        OAuth20Service authService = linkedOAuth2ServiceProducer.createOAuthService(req, null);
        OAuthRequest request = new OAuthRequest(Verb.GET, "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,picture-url,public-profile-url,email-address)?format=json");

        authService.signRequest(token, request);
        OAuth2UserToken linkedinUser;
        try {
            Response oResp = authService.execute(request);
            linkedinUser = jsonProcessor.extractLinkedinUser(oResp.getBody());
            if (linkedinUser != null) {
                linkedinUser.setToken(token);
            }

        } catch (InterruptedException | ExecutionException | IOException e) {
            throw new AtbashUnexpectedException(e);
        }
        return linkedinUser;

    }
}
