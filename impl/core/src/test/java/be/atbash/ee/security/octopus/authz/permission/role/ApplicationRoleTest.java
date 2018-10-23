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
package be.atbash.ee.security.octopus.authz.permission.role;

import be.atbash.util.exception.AtbashIllegalActionException;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.Assert;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ApplicationRoleTest {

    @Test
    public void equalsHashCodeContract() {

        EqualsVerifier.forClass(ApplicationRole.class)
                .withNonnullFields("name") // enforced by constructor
                .verify();

    }

    @Test
    public void instantiate() {

        new ApplicationRole("Atbash");

    }

    @Test
    public void instantiate_null() {

        try {
            new ApplicationRole(null);
            Assert.fail("Should thrown an AtbashIllegalActionException");
        } catch (AtbashIllegalActionException e) {
            assertThat(e.getMessage()).isEqualTo("(OCT-DEV-010) The name can't be empty for a ApplicationRole");
        }

    }

    @Test
    public void instantiate_empty() {

        try {
            new ApplicationRole("");
            Assert.fail("Should thrown an AtbashIllegalActionException");
        } catch (AtbashIllegalActionException e) {
            assertThat(e.getMessage()).isEqualTo("(OCT-DEV-010) The name can't be empty for a ApplicationRole");
        }
    }

    @Test
    public void instantiate_whitespace() {

        try {
            new ApplicationRole(" ");
            Assert.fail("Should thrown an AtbashIllegalActionException");
        } catch (AtbashIllegalActionException e) {
            assertThat(e.getMessage()).isEqualTo("(OCT-DEV-010) The name can't be empty for a ApplicationRole");
        }

    }

}