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
package be.atbash.ee.security.octopus.mp.token;


import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Represent the MP Auth token (can be used in a
 * //
 */
public class MPJWTToken implements Cloneable {

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
            "aud": "s6BhdRkqt3",MPJWTTokenTest
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

    /**
     * Sets the exp token value directly in seconds.
     *
     * @param exp This is the seconds value to set it directly. Do not use Date.getTime().
     */
    public void setExp(Long exp) {
        this.exp = exp;
    }

    /**
     * Sets the exp token value based on the Date instance.
     *
     * @param exp expiration indicated as date.
     */
    public void setExp(Date exp) {
        this.exp = DateUtils.toSecondsSinceEpoch(exp);
    }

    /**
     * Sets the exp token value based on the LocalDateTime instance.
     *
     * @param exp expiration indicated as LocalDateTime.
     */
    public void setExp(LocalDateTime exp) {
        this.exp = DateUtils.toSecondsSinceEpoch(exp);
    }

    public Long getIat() {
        return iat;
    }


    public void setIat(Long iat) {
        this.iat = iat;
    }

    public void setIat(Date iat) {
        this.iat = DateUtils.toSecondsSinceEpoch(iat);
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
