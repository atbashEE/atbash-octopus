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
package be.atbash.ee.security.octopus.authz.checks;

import be.atbash.ee.security.octopus.authz.annotation.*;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationUtil;
import be.atbash.ee.security.octopus.systemaccount.SystemAccount;
import be.atbash.util.exception.AtbashUnexpectedException;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.lang.annotation.Annotation;

import static be.atbash.ee.security.octopus.authz.checks.SecurityCheckCustomCheck.ADVANCED_FLAG;

/**
 *
 */
@ApplicationScoped
public class SecurityCheckDataFactory {

    @Inject
    private OctopusCoreConfiguration config;

    /**
     * Init dependencies in the Java SE Environment
     */
    public void initDependencies() {
        config = OctopusCoreConfiguration.getInstance();
    }

    public SecurityCheckData determineDataFor(Annotation annotation) {
        SecurityCheckType securityCheckType = determineType(annotation);
        if (securityCheckType == null) {
            throw new AtbashUnexpectedException(String.format("Unable to determine the security type of %s", annotation.getClass().getName()));
        }

        SecurityCheckData.SecurityCheckDataBuilder builder = new SecurityCheckData.SecurityCheckDataBuilder(securityCheckType);
        switch (securityCheckType) {

            case REQUIRES_PERMISSIONS:
            case REQUIRES_ROLES:
                builder.withCombination(AnnotationUtil.getPermissionCombination(annotation));
                builder.withValues(AnnotationUtil.getStringValues(annotation));
                break;
            case CUSTOM_VOTER:
                builder.withClassValues(((CustomVoterCheck) annotation).value());
                break;
            case ONLY_DURING_AUTHENTICATION:
            case ONLY_DURING_AUTHENTICATION_EVENT:
            case ONLY_DURING_AUTHORIZATION:
            case REQUIRES_AUTHENTICATION:
            case REQUIRES_GUEST:
            case REQUIRES_USER:
                break;

            case NAMED_PERMISSION:
                builder.withCombination(AnnotationUtil.getPermissionCombination(annotation));
                builder.withNamedPermissions(AnnotationUtil.getPermissionValues(annotation));
                break;
            case NAMED_ROLE:
                builder.withCombination(AnnotationUtil.getPermissionCombination(annotation));
                builder.withNamedRoles(AnnotationUtil.getRoleValues(annotation));
                break;
            case CUSTOM:
                builder.withClassValue(annotation.annotationType());
                builder.withValues(AnnotationUtil.getStringValues(annotation));
                builder.setParameter(ADVANCED_FLAG, AnnotationUtil.hasAdvancedFlag(annotation));
                break;

            case SYSTEM_ACCOUNT:
                builder.withValues(((SystemAccount) annotation).value());
                break;
        }
        return builder.build();
    }

    private SecurityCheckType determineType(Object annotation) {
        // FIXME Order based on expected usage.
        if (config.getCustomCheckClass() != null && config.getCustomCheckClass().isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.CUSTOM;
        }

        if (CustomVoterCheck.class.isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.CUSTOM_VOTER;
        }

        if (config.getNamedPermissionCheckClass() != null && config.getNamedPermissionCheckClass().isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.NAMED_PERMISSION;
        }
        if (config.getNamedRoleCheckClass() != null && config.getNamedRoleCheckClass().isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.NAMED_ROLE;
        }
        if (OnlyDuringAuthentication.class.isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.ONLY_DURING_AUTHENTICATION;
        }
        if (OnlyDuringAuthenticationEvent.class.isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.ONLY_DURING_AUTHENTICATION_EVENT;
        }
        if (OnlyDuringAuthorization.class.isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.ONLY_DURING_AUTHORIZATION;
        }
        if (RequiresAuthentication.class.isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.REQUIRES_AUTHENTICATION;
        }
        if (RequiresGuest.class.isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.REQUIRES_GUEST;
        }
        if (RequiresPermissions.class.isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.REQUIRES_PERMISSIONS;
        }
        if (RequiresRoles.class.isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.REQUIRES_ROLES;
        }
        if (RequiresUser.class.isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.REQUIRES_USER;
        }
        if (SystemAccount.class.isAssignableFrom(annotation.getClass())) {
            return SecurityCheckType.SYSTEM_ACCOUNT;
        }
        return null;

    }
}
