/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package be.atbash.ee.oauth2.sdk;


import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the scope token class.
 */
public class ScopeValueTest {

    @Test
    public void testMinimalConstructor() {

        Scope.Value t = new Scope.Value("read");

        assertThat(t.getValue()).isEqualTo("read");

        assertThat(t.getRequirement()).isNull();
    }

    @Test
    public void testFullConstructor() {

        Scope.Value t = new Scope.Value("write", Scope.Value.Requirement.OPTIONAL);

        assertThat(t.getValue()).isEqualTo("write");

        assertThat(t.getRequirement()).isEqualTo(Scope.Value.Requirement.OPTIONAL);
    }

    @Test
    public void testEquality() {

        Scope.Value t1 = new Scope.Value("read");
        Scope.Value t2 = new Scope.Value("read");

        assertThat(t1.equals(t2)).isTrue();
    }
}
