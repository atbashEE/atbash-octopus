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

import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.mp.config.MPCoreConfiguration;
import be.atbash.ee.security.octopus.subject.PrincipalConverter;
import be.atbash.ee.security.octopus.subject.Subject;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class MPPrincipalConverter implements PrincipalConverter<MPToken> {

    @Inject
    private MPCoreConfiguration coreConfiguration;

    @Inject
    private MPJWTTokenBuilder tokenBuilder;

    @Override
    public boolean supportFor(Class<MPToken> authenticationTokenClass) {
        return true;
    }

    @Override
    public MPToken convert(Subject subject) {
        checkDependencies(); // TODO Should we have some init method in interface so that we can call this when service loader has instantiated this?
        // FIXME We should have the possibility to set iss, aud etc .. dynamically based on the target URL.
        // FIXME So additional parameter is then required and the possibility to have an implementation of some new to define interface which can determine these values.
        MPJWTTokenBuilder builder = tokenBuilder.setSubject(subject.getPrincipal().getUserName());

        for (Permission permission : subject.getAllPermissions()) {
            if (permission instanceof NamedPermission) {
                builder.addGroup(((NamedPermission) permission).name());
            } else {
                builder.addGroup(permission.toString());  // RolePermission

            }
        }

        MPJWTToken mpjwtToken = builder.build();

        return new MPToken(mpjwtToken);
    }

    private void checkDependencies() {
        if (coreConfiguration == null) {
            tokenBuilder = new MPJWTTokenBuilder(); // Dependent scope so new instantiation fits here.
            tokenBuilder.init();
            coreConfiguration = MPCoreConfiguration.getInstance();
        }
    }

}
