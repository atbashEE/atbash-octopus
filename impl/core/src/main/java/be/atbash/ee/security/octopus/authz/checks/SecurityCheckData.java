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
package be.atbash.ee.security.octopus.authz.checks;

import be.atbash.ee.security.octopus.authz.Combined;
import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.role.NamedRole;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */

public class SecurityCheckData {

    private SecurityCheckType securityCheckType;

    private Combined permissionCombination = Combined.OR;
    private Class<?> classValue;
    private Class<?>[] classValues;

    private String[] values;

    private Map<String, Object> parameterMap = new HashMap<>();

    private NamedPermission[] permissionValues;
    private NamedRole[] roleValues;

    public SecurityCheckType getSecurityCheckType() {
        return securityCheckType;
    }

    public Combined getPermissionCombination() {
        return permissionCombination;
    }

    public String[] getValues() {
        return values;
    }

    public <T> T getParameter(String key, T defaultValue) {
        T result = (T) parameterMap.get(key);
        if (result == null) {
            result = defaultValue;
        }
        return result;
    }

    public Class<?> getClassValue() {
        return classValue;
    }

    public Class<?>[] getClassValues() {
        return classValues;
    }

    public NamedPermission[] getPermissionValues() {
        return permissionValues;
    }

    public NamedRole[] getRoleValues() {
        return roleValues;
    }

    public static class SecurityCheckDataBuilder {
        // FIXME Validate method parameters
        private SecurityCheckData data = new SecurityCheckData();

        public SecurityCheckDataBuilder(SecurityCheckType securityCheckType) {
            data.securityCheckType = securityCheckType;
        }

        public SecurityCheckDataBuilder withCombination(Combined combination) {
            data.permissionCombination = combination;
            return this;
        }

        public SecurityCheckDataBuilder withValues(String[] values) {
            data.values = values;
            return this;
        }

        public SecurityCheckDataBuilder withClassValue(Class<?> classValue) {
            data.classValue = classValue;
            return this;
        }

        public SecurityCheckDataBuilder withClassValues(Class<?>[] classValues) {
            data.classValues = classValues;
            return this;
        }

        public SecurityCheckDataBuilder setParameter(String key, Object value) {
            data.parameterMap.put(key, value);
            return this;
        }

        public SecurityCheckDataBuilder withNamedPermissions(NamedPermission[] permissionValues) {
            data.permissionValues = permissionValues;
            return this;
        }

        public SecurityCheckDataBuilder withNamedRoles(NamedRole[] roleValues) {
            data.roleValues = roleValues;
            return this;
        }

        public SecurityCheckData build() {
            return data;
        }

    }
}
