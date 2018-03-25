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
package be.atbash.ee.security.octopus.authz.permission.role.voter;

import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.role.ApplicationRole;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
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
import javax.inject.Inject;
import java.util.Set;

/**
 * Class used by Octopus Framework to create CDI beans for a voter which is capable of verifying if the
 * user has a {@link RolePermission} (which is a permission that acts as a Role that has a name.
 * It is created by the CDI extension when the typesafe enums are used
 * and created by the CDI producer for an Injection Point.
 * <code>
 * &amp;Inject
 * &amp;RequiresRoles("orderRead")
 * private GenericRoleVoter orderReadVoter;
 * </code>
 * <p>
 * Although not encouraged, the developer can also create  a voter manually (when no CDI available, but then {@link CDIUtils} is a better option, then the following 2 ways
 * <code>
 * GenericPermissionRole.createInstance(NamedApplicationRole);
 * </code>
 * and
 * <code>
 * GenericPermissionRole voter = new GenericPermissionRole();
 * voter.setNamedRole(NamedApplicationRole)
 * </code>
 */
@PublicAPI
@Typed
@Reviewed
public class GenericRoleVoter extends AbstractAccessDecisionVoter {

    @Inject
    private Subject subject;

    private Permission permission;

    /**
     * Set the Role (as special type of Permission) which will be verified on the subject. Should only be used when developer has instantiated the instance himself by using the keyword new.
     * Used by the framework internally.
     *
     * @param namedRole The role to verify/check
     */
    public void setNamedRole(ApplicationRole namedRole) {
        if (namedRole == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-008) namedRole can't be null");  // FIXME See how this can be null (used from Extension)
        }
        if (permission != null) {
            throw new AtbashIllegalActionException("(OCT-DEV-009) SimpleNamedRole already set and not allowed to change it.");
        }

        permission = new RolePermission(namedRole.name());
    }

    public void setNamedRole(RolePermission namedRole) {
        if (namedRole == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-008) namedRole can't be null");  // FIXME See how this can be null (used from Extension)
        }
        if (permission != null) {
            throw new AtbashIllegalActionException("(OCT-DEV-009) SimpleNamedRole already set and not allowed to change it.");
        }
        permission = namedRole;
    }

    @Override
    protected void checkPermission(AccessDecisionVoterContext accessDecisionVoterContext, Set<SecurityViolation> violations) {
        if (permission == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-008) namedRole can't be null");
        }
        if (subject == null) {
            // In the case the developer created a voter manually by calling new GenericRoleVoter(), although .createInstance() is preferred.
            // TODO Investigate if the extension can be updated so that the creation of the CDI bean for a GenericRole voter can be different (so not needing the setNamedRole()

            subject = CDIUtils.retrieveInstance(Subject.class);
        }

        try {
            subject.checkPermission(permission);
        } catch (AuthorizationException e) {
            SecurityViolationInfoProducer infoProducer = CDIUtils.retrieveInstance(SecurityViolationInfoProducer.class);
            violations.add(newSecurityViolation(infoProducer.getViolationInfo(accessDecisionVoterContext, permission)));

        }
    }

    /**
     * Also does the verification of the Role (Permission) but just return true or false and not the {@link SecurityViolation} itself.
     *
     * @return Has subject the role.
     */
    public boolean verifyPermission() {
        boolean result = true;
        try {
            subject.checkPermission(permission);
        } catch (AuthorizationException e) {
            result = false;
        }
        return result;
    }

    /**
     * Can be used to create an instance of the voter manually by the developer (if needed). Also used internally by the framework.
     *
     * @param namedRole The role to verify/check
     * @return Voter capable of verifying/checking the role.
     */
    public static GenericRoleVoter createInstance(ApplicationRole namedRole) {
        if (namedRole == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-008) namedRole can't be null");
        }

        GenericRoleVoter result = new GenericRoleVoter();
        result.subject = CDIUtils.retrieveInstance(Subject.class);
        result.permission = new RolePermission(namedRole.name());
        return result;
    }

    /**
     * Used internally by the framework, should never be called by the developer.
     *
     * @param namedRole The role to verify/check
     * @return Voter capable of verifying/checking the role.
     */
    public static GenericRoleVoter createInstance(RolePermission namedRole) {
        // Never null (called from be.atbash.ee.security.octopus.provider.NamedRoleProducer#getVoter()

        GenericRoleVoter result = new GenericRoleVoter();
        result.subject = CDIUtils.retrieveInstance(Subject.class);
        result.permission = namedRole;
        return result;
    }

}