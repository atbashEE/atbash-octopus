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
package be.atbash.ee.security.octopus.sso.core.token;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.sso.core.config.OctopusSSOConfiguration;
import be.atbash.ee.security.octopus.sso.core.rest.PrincipalUserInfoJSONProvider;
import be.atbash.ee.security.octopus.sso.core.rest.reflect.Property;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.util.StringUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.util.*;

import static be.atbash.ee.security.octopus.OctopusConstants.AUTHORIZATION_INFO;


/**
 * TODO On Java EE 8, use JSON-B for this.
 */
@ApplicationScoped
public class OctopusSSOTokenConverter {

    private static final String MARKER_CUSTOM_CLASS = "@@";

    @Inject
    private OctopusSSOConfiguration ssoConfiguration;

    @Inject
    private Logger logger;

    private static final List<String> DEFAULT_PROPERTY_NAMES = Arrays.asList("id", OctopusConstants.LOCAL_ID, "userName", OctopusConstants.LAST_NAME, OctopusConstants.FIRST_NAME, OctopusConstants.EMAIL);

    public UserInfo fromIdToken(JWTClaimsSet idTokenClaims) {
        return new UserInfo(idTokenClaims);
    }

    public Map<String, Object> asClaims(UserPrincipal userPrincipal, PrincipalUserInfoJSONProvider jsonProvider) {
        Map<String, Object> result = new HashMap<>();

        result.put("id", userPrincipal.getId());
        result.put(OctopusConstants.LOCAL_ID, userPrincipal.getLocalId());

        result.put(UserInfo.PREFERRED_USERNAME_CLAIM_NAME, userPrincipal.getUserName());

        result.put(UserInfo.FAMILY_NAME_CLAIM_NAME, userPrincipal.getLastName());
        result.put(UserInfo.GIVEN_NAME_CLAIM_NAME, userPrincipal.getFirstName());
        result.put(UserInfo.NAME_CLAIM_NAME, userPrincipal.getName());
        result.put(UserInfo.EMAIL_CLAIM_NAME, userPrincipal.getEmail());

        Map<String, Serializable> info = new HashMap<>(userPrincipal.getInfo());
        info.remove(OctopusConstants.TOKEN);
        info.remove(OctopusConstants.UPSTREAM_TOKEN);
        info.remove(AUTHORIZATION_INFO);

        List<String> keysToFilter = getKeysToFilter();
        for (String key : keysToFilter) {
            info.remove(key);
        }

        for (Map.Entry<String, Serializable> infoEntry : info.entrySet()) {

            Object value = infoEntry.getValue();
            if (Property.isBasicPropertyType(value)) {
                result.put(infoEntry.getKey(), value);
            } else {
                result.put(infoEntry.getKey(), value.getClass().getName() + MARKER_CUSTOM_CLASS + jsonProvider.writeValue(value));
            }
        }

        return result;
    }

    private List<String> getKeysToFilter() {
        List<String> result = new ArrayList<>();
        String[] keys = ssoConfiguration.getKeysToFilter().split(",");
        for (String key : keys) {
            result.add(key.trim());
        }
        return result;
    }

    public OctopusSSOToken fromUserInfo(UserInfo userInfo, PrincipalUserInfoJSONProvider jsonProvider) {
        OctopusSSOToken result = new OctopusSSOToken();

        Object localIdClaim = userInfo.getClaim(OctopusConstants.LOCAL_ID);
        result.setLocalId(localIdClaim == null ? null : localIdClaim.toString());  // Get String returns null for (short) numbers
        String preferredUsername = userInfo.getPreferredUsername();
        // with resourceOwnerPasswordCredentials, username is in "sub"
        String userName = preferredUsername == null ? userInfo.getStringClaim("sub") : preferredUsername;
        result.setUserName(userName);

        String id = userInfo.getStringClaim("id");
        result.setId(StringUtils.isEmpty(id) ? userName : id); //id is required.

        result.setLastName(userInfo.getFamilyName());
        result.setFirstName(userInfo.getGivenName());
        result.setFullName(userInfo.getName());
        result.setEmail(userInfo.getEmailAddress());

        Serializable value;

        JSONObject jsonObject = userInfo.toJSONObject();
        for (String keyName : jsonObject.keySet()) {

            if (!DEFAULT_PROPERTY_NAMES.contains(keyName)) {
                String keyValue = getString(jsonObject, keyName);
                if (keyValue.contains(MARKER_CUSTOM_CLASS)) {

                    Class<? extends Serializable> aClass = tryToDefineClass(keyValue);
                    if (aClass != null) {
                        int markerPos = keyValue.indexOf(MARKER_CUSTOM_CLASS);
                        value = jsonProvider.readValue(keyValue.substring(markerPos + MARKER_CUSTOM_CLASS.length()), aClass);
                    } else {
                        value = keyValue; // We don't have the class, we keep the string representation for convenience.
                    }

                } else {
                    value = keyValue;
                }
                result.addUserInfo(keyName, value);
            }
        }


        return result;
    }

    private Class<? extends Serializable> tryToDefineClass(String keyValue) {
        Class<? extends Serializable> result = null;
        String[] parts = keyValue.split("@@", 2);
        try {
            // asClaims() starts from a Serializable class, so this should always we ok.
            // TODO This needs to be reviewed when octopus-oauth2-se is against against other types then Octopus SSO Server.
            result = (Class<? extends Serializable>) Class.forName(parts[0]);
        } catch (ClassNotFoundException e) {
            // Nothing to do here, we don't have that class on the classpath
            logger.warn(String.format("Reading serialized userInfo data failed for OctopusSSOToken as class %s can't be located", parts[0]));
        }

        if (result != null && !checkDefaultConstructor(result)) {
            logger.warn(String.format("Reading serialized userInfo data failed for OctopusSSOToken as class %s doesn't have a default constructor", parts[0]));
            result = null;
        }

        return result;
    }

    private boolean checkDefaultConstructor(Class<?> aClass) {
        boolean result = false;
        for (Constructor<?> constructor : aClass.getConstructors()) {
            if (constructor.getParameterTypes().length == 0) {
                result = true;
                break;
            }
        }
        return result;
    }

    private static String getString(JSONObject jsonObject, String key) {
        Object keyValue = jsonObject.get(key);
        if (keyValue != null) {
            return keyValue.toString();
        } else {
            return "";
        }
    }

}
