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
package be.atbash.ee.security.octopus.oauth2.github.json;

import be.atbash.ee.security.octopus.authz.UnauthenticatedException;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import be.atbash.ee.security.octopus.oauth2.info.OAuth2UserInfoProcessor;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.enterprise.context.ApplicationScoped;
import javax.json.JsonObject;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class GithubJSONProcessor extends OAuth2UserInfoProcessor {
    // Constants in this class are specific for Github and thus we don't put them in OctopusConstants

    private static final List<String> KEYS = Arrays.asList("id", "email", "name", "url", "gravatar_url");

    public OAuth2UserToken extractGithubUser(String json) {
        OAuth2UserToken oAuth2User;
        try {
            JsonObject jsonObject = JSONObjectUtils.parse(json);

            if (!jsonObject.containsKey("error")) {
                oAuth2User = new OAuth2UserToken();
                oAuth2User.setId(jsonObject.getString("id"));
                oAuth2User.setEmail(jsonObject.getString("email"));

                oAuth2User.setFullName(optString(jsonObject, "name"));

                oAuth2User.setLink(optString(jsonObject, "url"));

                oAuth2User.setPicture(optString(jsonObject, "gravatar_url"));

                processJSON(oAuth2User, jsonObject, KEYS);

            } else {
                logger.warn("Received following response from Github token resolving \n" + json);
                throw new UnauthenticatedException(json);
            }

        } catch (ParseException e) {
            logger.warn(e.getMessage(), e);
            throw new AtbashUnexpectedException(e);
        }
        return oAuth2User;
    }

}
