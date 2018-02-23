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
package be.atbash.ee.security.octopus.authz.permission.typesafe;

import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.testclasses.TestPermission;
import be.atbash.util.BeanManagerFake;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */

public final class PermissionLookupFixture {

    public static void registerPermissionLookup(BeanManagerFake beanManagerFake) {
        List<NamedDomainPermission> allPermissions = new ArrayList<>();
        allPermissions.add(new NamedDomainPermission("PERMISSION1", "Permission:1:*"));
        allPermissions.add(new NamedDomainPermission("PERMISSION2", "Permission:2:*"));
        allPermissions.add(new NamedDomainPermission("PERMISSION3", "Permission:3:*"));
        PermissionLookup permissionLookup = new PermissionLookup<>(allPermissions, TestPermission.class);
        beanManagerFake.registerBean(permissionLookup, PermissionLookup.class);
    }

}