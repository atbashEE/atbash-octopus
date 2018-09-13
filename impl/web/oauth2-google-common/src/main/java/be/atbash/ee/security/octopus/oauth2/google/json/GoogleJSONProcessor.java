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
package be.atbash.ee.security.octopus.oauth2.google.json;


import be.atbash.ee.security.octopus.authz.UnauthenticatedException;
import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import be.atbash.ee.security.octopus.oauth2.info.OAuth2UserInfoProcessor;
import be.atbash.json.JSONObject;
import be.atbash.json.parser.JSONParser;
import be.atbash.json.parser.ParseException;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.enterprise.context.ApplicationScoped;
import java.util.Arrays;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class GoogleJSONProcessor extends OAuth2UserInfoProcessor {
    // Constants in this class are specific for Google and thus we don't put them in OctopusConstants

    private static final List<String> KEYS = Arrays.asList("sub", "email", "verified_email", "family_name", "given_name", "name", "hd", "link", "picture", "gender", "locale");

    public OAuth2UserToken extractGoogleUser(String json) {
        OAuth2UserToken oAuth2User;
        try {
            JSONParser parser = new JSONParser(JSONParser.MODE_PERMISSIVE);

            JSONObject jsonObject = (JSONObject) parser.parse(json);

            if (!jsonObject.containsKey("error")) {
                oAuth2User = new OAuth2UserToken();
                oAuth2User.setId(getString(jsonObject, "sub"));
                oAuth2User.setEmail(getString(jsonObject, "email"));

                oAuth2User.setVerifiedEmail(optBoolean(jsonObject, "verified_email"));
                oAuth2User.setLastName(optString(jsonObject, "family_name"));
                oAuth2User.setFirstName(optString(jsonObject, "given_name"));
                oAuth2User.setFullName(optString(jsonObject, "name"));
                oAuth2User.setDomain(optString(jsonObject, "hd"));
                oAuth2User.setLink(optString(jsonObject, "link"));
                oAuth2User.setPicture(optString(jsonObject, "picture"));
                oAuth2User.setGender(optString(jsonObject, "gender"));
                oAuth2User.setLocale(optString(jsonObject, "locale"));

                processJSON(oAuth2User, jsonObject, KEYS);
            } else {
                logger.warn("Received following response from Google token resolving \n" + json);
                throw new UnauthenticatedException(json);
            }

        } catch (ParseException e) {
            logger.warn(e.getMessage(), e);
            throw new AtbashUnexpectedException(e);
        }
        return oAuth2User;
    }

    private boolean optBoolean(JSONObject jsonObject, String key) {
        String value = optString(jsonObject, key);
        if (value != null) {
            return Boolean.valueOf(value);
        } else {
            return false;
        }
    }

}
