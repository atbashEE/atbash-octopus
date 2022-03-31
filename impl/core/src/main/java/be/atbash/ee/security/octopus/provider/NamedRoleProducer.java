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
package be.atbash.ee.security.octopus.provider;

import be.atbash.ee.security.octopus.authz.annotation.RequiresRoles;
import be.atbash.ee.security.octopus.authz.permission.role.NamedRole;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.authz.permission.role.voter.GenericRoleVoter;
import be.atbash.ee.security.octopus.authz.permission.typesafe.RoleLookup;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.names.VoterNameFactory;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationUtil;
import be.atbash.util.CDIUtils;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.AmbiguousResolutionException;
import jakarta.enterprise.inject.Produces;
import jakarta.enterprise.inject.UnsatisfiedResolutionException;
import jakarta.enterprise.inject.spi.InjectionPoint;
import jakarta.inject.Inject;
import java.lang.annotation.Annotation;

@ApplicationScoped
public class NamedRoleProducer extends AbstractProducer {

    @Inject
    private OctopusCoreConfiguration config;

    @Inject
    private VoterNameFactory nameFactory;

    private RoleLookup<? extends NamedRole> lookup;

    @PostConstruct
    public void init() {
        // Optional to make sure that if the bean is not created without actually needing it, we don't get into trouble if the lookup isn't defined.
        lookup = CDIUtils.retrieveOptionalInstance(RoleLookup.class);
    }

    @Produces
    public GenericRoleVoter getVoter(InjectionPoint injectionPoint) {
        GenericRoleVoter result = null;

        Annotation annotation = null;

        Class<? extends Annotation> namedRoleCheckClass = config.getNamedRoleCheckClass();
        if (namedRoleCheckClass != null) {
            annotation = injectionPoint.getAnnotated().getAnnotation(namedRoleCheckClass);
        }

        if (annotation != null) {
            NamedRole[] roles = AnnotationUtil.getRoleValues(annotation);
            if (roles.length > 1) {
                throw new AmbiguousResolutionException(String.format("Only one role permission can be specified at %s", defineInjectionPointInfo(injectionPoint)));
            }

            result = CDIUtils.retrieveInstanceByName(nameFactory.generateRoleBeanName(roles[0].name()), GenericRoleVoter.class);

        }

        if (result == null) {
            annotation = injectionPoint.getAnnotated().getAnnotation(RequiresRoles.class);
            if (annotation != null) {
                String[] roleNames = AnnotationUtil.getStringValues(annotation);
                if (roleNames.length > 1) {
                    // FIXME Document with (OCT-DEV-
                    throw new AmbiguousResolutionException(String.format("Only one role permission can be specified at %s", defineInjectionPointInfo(injectionPoint)));
                }

                if (lookup != null) {
                    RolePermission namedRole = lookup.getRole(roleNames[0]);
                    result = GenericRoleVoter.createInstance(namedRole);
                }
                if (result == null) {
                    RolePermission permission = new RolePermission(roleNames[0]);
                    result = GenericRoleVoter.createInstance(permission);
                }

            }
        }

        if (result == null) {
            throw new UnsatisfiedResolutionException(
                    // FIXME Document with (OCT-DEV-
                    String.format("Injection points for GenericRoleVoter needs an additional %s annotation to determine the correct bean at %s"
                            , getInjectPointAnnotationText(), defineInjectionPointInfo(injectionPoint))
            );
        }

        return result;
    }

    private String getInjectPointAnnotationText() {
        StringBuilder result = new StringBuilder();
        result.append(RequiresRoles.class.getName());
        if (config.getNamedRoleCheckClass() != null) {
            result.append(" or ").append(config.getNamedRoleCheckClass().getName());
        }
        return result.toString();
    }

    @Produces
    public RolePermission getRole(InjectionPoint injectionPoint) {
        RolePermission result = null;

        Annotation annotation = null;

        Class<? extends Annotation> namedRoleCheckClass = config.getNamedRoleCheckClass();
        if (namedRoleCheckClass != null) {
            annotation = injectionPoint.getAnnotated().getAnnotation(namedRoleCheckClass);
        }

        if (annotation != null) {
            NamedRole[] roles = AnnotationUtil.getRoleValues(annotation);
            if (roles.length > 1) {
                throw new AmbiguousResolutionException(String.format("Only one role permission can be specified at %s", defineInjectionPointInfo(injectionPoint)));
            }

            // With getNamedRoleCheckClass defined, the roleLookup is also required
            result = lookup.getRole(roles[0].name());

        }

        if (result == null) {
            annotation = injectionPoint.getAnnotated().getAnnotation(RequiresRoles.class);
            if (annotation != null) {
                String[] roleNames = AnnotationUtil.getStringValues(annotation);
                if (roleNames.length > 1) {
                    // FIXME Document with (OCT-DEV-
                    throw new AmbiguousResolutionException(String.format("Only one role permission can be specified at %s", defineInjectionPointInfo(injectionPoint)));
                }

                if (lookup != null) {
                    result = lookup.getRole(roleNames[0]);
                }
                if (result == null) {
                    result = new RolePermission(roleNames[0]);
                }

            }
        }
        if (result == null) {
            throw new UnsatisfiedResolutionException(
                    // FIXME Document with (OCT-DEV-
                    String.format("Injection points for NamedApplicationRole needs an additional %s annotation to determine the correct bean at %s"
                            , getInjectPointAnnotationText(), defineInjectionPointInfo(injectionPoint))
            );
        }

        return result;

    }

}
