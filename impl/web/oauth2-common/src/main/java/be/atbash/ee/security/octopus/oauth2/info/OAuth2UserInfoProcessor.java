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
package be.atbash.ee.security.octopus.oauth2.info;

import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.json.JsonObject;
import java.io.Serializable;
import java.util.Iterator;
import java.util.List;

/**
 *
 */
public abstract class OAuth2UserInfoProcessor {

    protected Logger logger = LoggerFactory.getLogger(getClass());

    protected void processJSON(OAuth2UserToken oAuth2User, JsonObject jsonObject, List<String> excludeKeys) {
        Iterator<String> keys = jsonObject.keySet().iterator();
        String key;
        while (keys.hasNext()) {
            key = keys.next();
            if (!excludeKeys.contains(key)) {
                Object info = jsonObject.get(key);
                if (info instanceof Serializable) {
                    oAuth2User.addUserInfo(key, (Serializable) info);
                } else {
                    if (info != null) {
                        oAuth2User.addUserInfo(key, info.toString());
                    }
                }
            }
        }
    }

    protected String optString(JsonObject jsonObject, String key) {
        if (jsonObject.containsKey(key)) {
            return jsonObject.getString(key);
        } else {
            return null;
        }
    }
}
