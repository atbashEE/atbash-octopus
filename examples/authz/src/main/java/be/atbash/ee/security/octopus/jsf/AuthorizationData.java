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
package be.atbash.ee.security.octopus.jsf;

import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.AuthorizationInfoProvider;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.typesafe.PermissionLookup;
import be.atbash.ee.security.octopus.jsf.security.DemoPermission;
import be.atbash.ee.security.octopus.realm.AuthorizationInfoBuilder;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class AuthorizationData implements AuthorizationInfoProvider {

    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        UserPrincipal userPrincipal = (UserPrincipal) principals.getPrimaryPrincipal();

        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        // When permissions are stored in database, they are probably added as NamedDomainPermission.
        builder.addPermission(DemoPermission.BASIC_PERMISSION);
        if ("admin".equals(userPrincipal.getUserName())) {
            builder.addPermission(DemoPermission.ADVANCED_PERMISSION);
        }

        return builder.build();

    }

    @ApplicationScoped
    @Produces
    public PermissionLookup<DemoPermission> buildLookup() {

        List<NamedDomainPermission> allPermissions = new ArrayList<>();
        allPermissions.add(new NamedDomainPermission("BASIC_PERMISSION", "permission:basic:*"));
        allPermissions.add(new NamedDomainPermission("ADVANCED_PERMISSION", "permission:advanced:*"));
        return new PermissionLookup<>(allPermissions, DemoPermission.class);
    }

}
