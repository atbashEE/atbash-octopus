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
package be.atbash.ee.security.octopus.token;

import be.atbash.json.JSONAware;
import be.atbash.json.JSONObject;
import be.atbash.json.parser.MappedBy;
import net.minidev.json.JSONArray;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represent the MP Auth token (can be used in a
 */
@MappedBy(beanEncoder = MPJWTTokenMapper.class)
public class MPJWTToken implements JSONAware, Cloneable {

    private String iss; // issuer
    private String aud; // audience
    private String jti; // Unique identifier
    private Long exp; // expiration time
    private Long iat; // issued at
    private String sub; // subject
    private String upn; // value for name in Principal
    private String preferredUsername;  // value for name in Principal
    private List<String> groups = new ArrayList<>();
        /*
    "iss": "https://server.example.com",
            "aud": "s6BhdRkqt3",
            "jti": "a-123",
            "exp": 1311281970,
            "iat": 1311280970,
            "sub": "24400320",
            "upn": "jdoe@server.example.com",
            "groups": ["red-group", "green-group", "admin-group", "admin"],
    */

    private List<String> roles;
    private Map<String, String> additionalClaims;

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(Long iat) {
        this.iat = iat;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getUpn() {
        return upn;
    }

    public void setUpn(String upn) {
        this.upn = upn;
    }

    public String getPreferredUsername() {
        return preferredUsername;
    }

    public void setPreferredUsername(String preferredUsername) {
        this.preferredUsername = preferredUsername;
    }

    public List<String> getGroups() {
        return groups;
    }

    public void setGroups(List<String> groups) {
        this.groups = groups;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public Map<String, String> getAdditionalClaims() {
        return additionalClaims;
    }

    public void setAdditionalClaims(Map<String, String> additionalClaims) {
        this.additionalClaims = additionalClaims;
    }

    public void addAdditionalClaims(String key, String value) {
        if (additionalClaims == null) {
            additionalClaims = new HashMap<>();
        }
        additionalClaims.put(key, value);
    }

    @Override
    public String toJSONString() {

        JSONObject jsonObject = new JSONObject();
        jsonObject.appendField("iss", iss);
        jsonObject.appendField("aud", aud);
        jsonObject.appendField("jti", jti);
        jsonObject.appendField("exp", exp / 1000);
        jsonObject.appendField("iat", iat / 1000);
        jsonObject.appendField("sub", sub);
        jsonObject.appendField("upn", upn);
        jsonObject.appendField("preferred_username", preferredUsername);
        // FIXME The other properties

        if (additionalClaims != null) {
            for (Map.Entry<String, String> entry : additionalClaims.entrySet()) {
                jsonObject.appendField(entry.getKey(), entry.getValue());
            }
        }

        JSONArray groupsArr = new JSONArray();
        for (String group : groups) {
            groupsArr.appendElement(group);
        }
        jsonObject.appendField("groups", groupsArr);

        return jsonObject.toJSONString();
    }

    // FIXME Is this a real clone or just a duplicate?
    @Override
    public Object clone() throws CloneNotSupportedException {
        MPJWTToken result = new MPJWTToken();
        result.iss = iss;
        result.aud = aud;
        result.jti = jti;
        result.exp = exp;
        result.iat = iat;
        result.sub = sub;
        result.upn = upn;
        result.groups = new ArrayList<>(groups);

        if (roles != null) {
            result.roles = new ArrayList<>(roles);
        }
        if (additionalClaims != null) {
            result.additionalClaims = new HashMap<>(additionalClaims);
        }

        return result;

    }
}
