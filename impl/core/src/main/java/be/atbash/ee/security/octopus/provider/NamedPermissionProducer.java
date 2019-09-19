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
package be.atbash.ee.security.octopus.provider;

import be.atbash.ee.security.octopus.authz.annotation.RequiresPermissions;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.StringPermissionLookup;
import be.atbash.ee.security.octopus.authz.permission.typesafe.PermissionLookup;
import be.atbash.ee.security.octopus.authz.permission.voter.GenericPermissionVoter;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.names.VoterNameFactory;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationUtil;
import be.atbash.util.CDIUtils;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.AmbiguousResolutionException;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.UnsatisfiedResolutionException;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;
import java.lang.annotation.Annotation;

@ApplicationScoped
public class NamedPermissionProducer extends AbstractProducer {

    @Inject
    private OctopusCoreConfiguration config;

    @Inject
    private VoterNameFactory nameFactory;

    private PermissionLookup<? extends NamedPermission> lookup;

    private StringPermissionLookup stringLookup;

    @PostConstruct
    public void init() {
        // Optional to make sure that if the bean is created without actually needing it, we don't get into trouble if the lookup isn't defined.
        lookup = CDIUtils.retrieveOptionalInstance(PermissionLookup.class);

        stringLookup = CDIUtils.retrieveOptionalInstance(StringPermissionLookup.class);
        if (stringLookup == null) {
            // Developer hasn't defined a producer for it, so let create an instance with no mapped permissions.
            // So they need to use always wildcardStrings!!
            stringLookup = new StringPermissionLookup();
        }
    }

    // FIXME Create IT test for this
    @Produces
    public GenericPermissionVoter getVoter(InjectionPoint injectionPoint) {
        NamedPermission[] permissions;

        GenericPermissionVoter result = null;

        if (config.getNamedPermissionCheckClass() != null) {
            Annotation annotation = injectionPoint.getAnnotated().getAnnotation(config.getNamedPermissionCheckClass());
            if (annotation != null) {
                permissions = AnnotationUtil.getPermissionValues(annotation);
                if (permissions.length > 1) {
                    throw new AmbiguousResolutionException(String.format("Only one named permission can be specified at %s", defineInjectionPointInfo(injectionPoint)));
                }
                result = CDIUtils.retrieveInstanceByName(nameFactory.generatePermissionBeanName(permissions[0].name()), GenericPermissionVoter.class);
            }
        }

        if (result == null) {
            RequiresPermissions requiresPermissions = injectionPoint.getAnnotated().getAnnotation(RequiresPermissions.class);
            if (requiresPermissions != null) {

                String[] stringPermissions = requiresPermissions.value();
                if (stringPermissions.length > 1) {
                    throw new AmbiguousResolutionException(String.format("Only one named permission can be specified at %s", defineInjectionPointInfo(injectionPoint)));
                }

                if (StringUtils.isEmpty(stringPermissions[0]) && requiresPermissions.permission().length == 0) {
                    throw new UnsatisfiedResolutionException(String.format("Value or permission attribute is required at %s", defineInjectionPointInfo(injectionPoint)));
                }
                // See remarks at init() about the usage of StringLookup, even if the developer hasn't defined one
                NamedDomainPermission permission = stringLookup.getPermission(stringPermissions[0]);

                // TODO Verify if permission can be null
                // TODO CDI Bean is dependent, can we cache it here since it could be application scoped but then we can't change NamedDomainPermission

                result = GenericPermissionVoter.createInstance(permission);
            }
        }

        if (result == null) {

            throw new UnsatisfiedResolutionException(
                    String.format("Injection points for GenericPermissionVoter needs an additional %s annotation to determine the correct bean at %s"
                            , getInjectPointAnnotationText(), defineInjectionPointInfo(injectionPoint))
            );
        }

        return result;
    }

    @Produces
    public NamedDomainPermission getPermission(InjectionPoint injectionPoint) {
        Class<? extends Annotation> namedPermissionCheckClass = config.getNamedPermissionCheckClass();

        NamedDomainPermission result = null;

        if (namedPermissionCheckClass != null) {

            Annotation annotation = injectionPoint.getAnnotated().getAnnotation(namedPermissionCheckClass);

            if (annotation != null) {
                NamedPermission[] permissions = AnnotationUtil.getPermissionValues(annotation);
                if (permissions.length > 1) {
                    throw new AmbiguousResolutionException(String.format("Only one named permission can be specified at %s", defineInjectionPointInfo(injectionPoint)));
                }

                // When we have NamedPermissionCheckClass, lookup is required.
                if (lookup == null) {
                    throw new AtbashIllegalActionException("(OCT-DEV-???) PermissionLookup definition is required when using custom NamedPermissionCheck class.");
                }
                result = lookup.getPermission(permissions[0].name());
            }
        }

        if (result == null) {
            RequiresPermissions requiresPermissions = injectionPoint.getAnnotated().getAnnotation(RequiresPermissions.class);
            if (requiresPermissions != null) {

                String[] stringPermissions = requiresPermissions.value();
                if (stringPermissions.length > 1) {
                    throw new AmbiguousResolutionException(String.format("Only one named permission can be specified at %s", defineInjectionPointInfo(injectionPoint)));
                }

                if (StringUtils.isEmpty(stringPermissions[0]) && requiresPermissions.permission().length == 0) {
                    throw new UnsatisfiedResolutionException(String.format("Value or permission attribute is required at %s", defineInjectionPointInfo(injectionPoint)));
                }

                // See remarks at init() about the usage of StringLookup, even if the developer hasn't defined one
                result = stringLookup.getPermission(stringPermissions[0]);
            }
        }

        if (result == null) {
            throw new UnsatisfiedResolutionException(
                    String.format("Injection points for NamedDomainPermission needs an additional %s annotation to determine the correct bean at %s"
                            , getInjectPointAnnotationText(), defineInjectionPointInfo(injectionPoint))
            );
        }

        return result;
    }

    private String getInjectPointAnnotationText() {
        StringBuilder result = new StringBuilder();
        result.append(RequiresPermissions.class.getName());
        if (config.getNamedPermissionCheckClass() != null) {
            result.append(" or ").append(config.getNamedPermissionCheckClass().getName());
        }
        return result.toString();
    }

}
