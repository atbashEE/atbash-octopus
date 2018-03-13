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

import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.PermissionResolver;
import be.atbash.ee.security.octopus.authz.permission.voter.AbstractGenericVoter;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.config.names.VoterNameFactory;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationUtil;
import be.atbash.ee.security.octopus.realm.AuthorizingRealm;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.CDIUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.deltaspike.security.spi.authorization.EditableAccessDecisionVoterContext;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.lang.annotation.Annotation;
import java.util.HashSet;
import java.util.Set;

/**
 * SecurityCheck for the annotation defined by OctopusConfig.getCustomCheckClass().
 */
@ApplicationScoped
public class SecurityCheckCustomCheck implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Inject
    private OctopusCoreConfiguration config;

    @Inject
    private VoterNameFactory nameFactory;

    @Inject
    private PermissionResolver permissionResolver;

    @Inject
    private AuthorizingRealm realm;

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, Annotation securityAnnotation) {
        SecurityCheckInfo result;

        if (!subject.isAuthenticated()) {
            result = SecurityCheckInfo.withException(
                    new SecurityViolationException("User required", infoProducer.getViolationInfo(accessContext))
            );
        } else {
            // TODO Check on EditableAccessDecisionVoterContext (maybe check immediatly on OctopusAccessDecisionVoterContext ??)
            Set<SecurityViolation> securityViolations = performCustomCheck(subject, securityAnnotation, (EditableAccessDecisionVoterContext) accessContext);
            if (!securityViolations.isEmpty()) {
                result = SecurityCheckInfo.withException(new SecurityViolationException(securityViolations));
            } else {
                result = SecurityCheckInfo.allowAccess();
            }
        }

        return result;
    }

    private Set<SecurityViolation> performCustomCheck(Subject subject, Annotation customCheck, EditableAccessDecisionVoterContext context) {

        String beanName = nameFactory.generateCustomCheckBeanName(customCheck.annotationType().getSimpleName());

        AbstractGenericVoter voter = CDIUtils.retrieveInstanceByName(beanName, AbstractGenericVoter.class);
        if (voter == null) {
            throw new ConfigurationException(String.format("An AbstractGenericVoter CDI bean with name %s cannot be found. Custom check annotation feature requirement", beanName));
        }

        if (!AnnotationUtil.hasAdvancedFlag(customCheck)) {

            String[] permissionStringValue = AnnotationUtil.getStringValues(customCheck);
            if (permissionStringValue == null || permissionStringValue.length != 1) {
                throw new IllegalArgumentException(String.format("value member of %s annotation can only have a single String value", customCheck.annotationType().getName()));
            }
            Permission permission = permissionResolver.resolvePermission(permissionStringValue[0]);
            context.addMetaData(Permission.class.getName(), realm.getMatchingPermissions(subject, permission));

        }

        Set<SecurityViolation> violations = voter.checkPermission(context);
        return new HashSet<>(violations);
    }

    @Override
    public boolean hasSupportFor(Object annotation) {
        return config.getCustomCheckClass() != null && config.getCustomCheckClass().isAssignableFrom(annotation.getClass());
    }
}
