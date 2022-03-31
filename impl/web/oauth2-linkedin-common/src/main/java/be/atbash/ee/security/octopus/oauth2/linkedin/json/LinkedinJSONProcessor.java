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
package be.atbash.ee.security.octopus.oauth2.linkedin.json;

import be.atbash.ee.security.octopus.authz.UnauthenticatedException;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import be.atbash.ee.security.octopus.oauth2.info.OAuth2UserInfoProcessor;
import be.atbash.util.exception.AtbashUnexpectedException;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.json.JsonObject;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class LinkedinJSONProcessor extends OAuth2UserInfoProcessor {
    // Constants in this class are specific for LinkedIn and thus we don't put them in OctopusConstants
    private static final List<String> KEYS = Arrays.asList("id", "emailAddress", "publicProfileUrl", "pictureUrl");

    public OAuth2UserToken extractLinkedinUser(String json) {
        OAuth2UserToken oAuth2User;
        try {
            JsonObject jsonObject = JSONObjectUtils.parse(json);

            if (!jsonObject.containsKey("error")) {
                oAuth2User = new OAuth2UserToken();
                oAuth2User.setId(jsonObject.getString("id"));
                oAuth2User.setEmail(jsonObject.getString("emailAddress"));

                oAuth2User.setFullName(optString(jsonObject, "lastName") + " " + optString(jsonObject, "firstName"));

                oAuth2User.setLink(optString(jsonObject, "publicProfileUrl"));

                oAuth2User.setPicture(optString(jsonObject, "pictureUrl"));

                processJSON(oAuth2User, jsonObject, KEYS);

            } else {
                logger.warn("Received following response from LinkedIn token resolving \n" + json);
                throw new UnauthenticatedException(json);
            }

        } catch (ParseException e) {
            logger.warn(e.getMessage(), e);
            throw new AtbashUnexpectedException(e);
        }
        return oAuth2User;
    }

}
