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
package be.atbash.ee.security.octopus.authz.permission;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class StringPermissionLookupTest {

    @Test
    public void getPermission() {
        StringPermissionLookup lookup = new StringPermissionLookup();
        NamedDomainPermission permission = lookup.getPermission("atbash");
        assertThat(permission).isNotNull();
        assertThat(permission.getName()).isEqualTo("atbash");
        assertThat(permission.getWildcardNotation()).isEqualTo("atbash");

    }

    @Test
    public void getPermission_WildCard() {
        StringPermissionLookup lookup = new StringPermissionLookup();
        NamedDomainPermission permission = lookup.getPermission("atbash:*:*");
        assertThat(permission).isNotNull();
        assertThat(permission.getName()).isEqualTo("atbash:*:*");
        assertThat(permission.getWildcardNotation()).isEqualTo("atbash:*:*");
    }

    @Test
    public void getPermission_NamedLookup() {
        List<NamedDomainPermission> allPermissions = new ArrayList<>();
        allPermissions.add(new NamedDomainPermission("AtbashPermName", "atbash:defined:perm"));
        StringPermissionLookup lookup = new StringPermissionLookup(allPermissions);
        NamedDomainPermission permission = lookup.getPermission("atbashpermname");
        assertThat(permission).isNotNull();
        assertThat(permission.getName()).isEqualTo("AtbashPermName");
        assertThat(permission.getWildcardNotation()).isEqualTo("atbash:defined:perm");
    }
}