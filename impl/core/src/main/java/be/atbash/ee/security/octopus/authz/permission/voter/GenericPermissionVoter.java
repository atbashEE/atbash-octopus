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
package be.atbash.ee.security.octopus.authz.permission.voter;

import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.CDIUtils;
import be.atbash.util.PublicAPI;
import be.atbash.util.Reviewed;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.apache.deltaspike.security.api.authorization.AbstractAccessDecisionVoter;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import javax.enterprise.inject.Typed;
import javax.enterprise.inject.Vetoed;
import javax.inject.Inject;
import java.util.Set;

/**
 * Class used by Octopus Framework to create CDI beans for a voter which is capable of verifying if the
 * user has a {@link NamedDomainPermission}. It is created by the CDI extension when the typesafe enums are used
 * and created by the CDI producer for an Injection Point.
 * <code>
 * &amp;Inject
 * &amp;RequiresPermissions("order:read:*")
 * private GenericPermissionVoter orderReadVoter;
 * </code>
 * <p>
 * Although not encouraged, the developer can also create  a voter manually (when no CDI available, but then {@link CDIUtils} is a better option, in the following 2 ways
 * <code>
 * GenericPermissionVoter.createInstance(NamedDomainPermission);
 * </code>
 * and
 * <code>
 * GenericPermissionVoter voter = new GenericPermission();
 * voter.setNamedPermission(NamedDomainPermission)
 * </code>
 */
@Typed
@PublicAPI
@Reviewed
public class GenericPermissionVoter extends AbstractAccessDecisionVoter {

    private Subject subject;

    private NamedDomainPermission namedPermission;

    /**
     * Set the Permission which will be verified on the subject. Should only be used when developer has instantiated the instance himself by using the keyword new.
     * Used by the framework internally.
     *
     * @param namedPermission The permission to verify/check
     */
    public void setNamedPermission(NamedDomainPermission namedPermission) {
        if (namedPermission == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-006) namedPermission can't be null");  // FIXME See how this can be null (used from Extension)
        }
        if (this.namedPermission != null) {
            throw new AtbashIllegalActionException("(OCT-DEV-007) NamedDomainPermission already set and not allowed to change it.");
        }
        this.namedPermission = namedPermission;
    }

    @Override
    protected void checkPermission(AccessDecisionVoterContext accessDecisionVoterContext, Set<SecurityViolation> violations) {
        if (namedPermission == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-006) namedPermission can't be null");
        }
        if (subject == null) {
            // TODO Investigate if the extension can be updated so that the creation of the CDI bean for a GenericPermission voter can be different (so not needing the setNamedPermission()
            // FIXME Review as in some environments the @Inject is validated during deployment although it is defined as @Typed or @Vetoed

            subject = CDIUtils.retrieveInstance(Subject.class);
        }
        try {
            subject.checkPermission(namedPermission);
        } catch (AuthorizationException e) {
            SecurityViolationInfoProducer infoProducer = CDIUtils.retrieveInstance(SecurityViolationInfoProducer.class);
            violations.add(newSecurityViolation(infoProducer.getViolationInfo(accessDecisionVoterContext, namedPermission)));
        }
    }

    /**
     * Also does the verification of the Permission but just return true or false and not the {@link SecurityViolation} itself.
     *
     * @return Has subject the permission (or equivalent through wildcards)
     */
    public boolean verifyPermission() {
        return subject.isPermitted(namedPermission);
    }

    /**
     * Can be used to create an instance of the voter manually by the developer (if needed). Also used internally by the framework.
     *
     * @param namedPermission The permission to verify/check
     * @return Voter capable of verifying/checking the permission.
     */
    public static GenericPermissionVoter createInstance(NamedDomainPermission namedPermission) {
        if (namedPermission == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-006) namedPermission can't be null");
        }

        GenericPermissionVoter result = new GenericPermissionVoter();
        result.subject = CDIUtils.retrieveInstance(Subject.class);
        result.namedPermission = namedPermission;
        return result;
    }
}
