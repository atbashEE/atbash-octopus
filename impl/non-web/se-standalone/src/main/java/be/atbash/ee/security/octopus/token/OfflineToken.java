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

import be.atbash.ee.security.octopus.authz.OfflineTokenAuthorizationProvider;
import be.atbash.ee.security.octopus.authz.TokenBasedAuthorizationInfoProvider;
import be.atbash.ee.security.octopus.authz.permission.Permission;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

/**
 * Define the contents of an offline token. It is generated for a user/application combination to
 * supply authentication and authorization information (name, permissions, roles, validity, ...)
 * Applications are CLI applications like batch jobs, Swing, Java FX programs.
 */

public class OfflineToken implements AuthenticationToken, AuthorizationToken, ValidatedAuthenticationToken {

    public static String LOCAL_SECRET_KEY_ID = "local secret";

    private Serializable id;

    private String subject;
    private String name;
    private List<String> audience;
    private List<Permission> permissions;
    private List<String> roles;
    private Date validFrom;
    private Date validUntil;

    public Serializable getId() {
        return id;
    }

    public void setId(Serializable id) {
        this.id = id;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    public List<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<Permission> permissions) {
        this.permissions = permissions;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public Date getValidUntil() {
        return validUntil;
    }

    public void setValidUntil(Date validUntil) {
        this.validUntil = validUntil;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Class<? extends TokenBasedAuthorizationInfoProvider> authorizationProviderClass() {
        return OfflineTokenAuthorizationProvider.class;
    }
}
