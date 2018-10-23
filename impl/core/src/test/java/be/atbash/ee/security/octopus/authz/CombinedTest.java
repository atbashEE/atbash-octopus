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
package be.atbash.ee.security.octopus.authz;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class CombinedTest {

    @Test
    public void findFor_or() {
        assertThat(Combined.findFor("or")).isEqualTo(Combined.OR);
        assertThat(Combined.findFor("OR")).isEqualTo(Combined.OR);
    }

    @Test
    public void findFor_and() {
        assertThat(Combined.findFor("and")).isEqualTo(Combined.AND);
        assertThat(Combined.findFor("AND")).isEqualTo(Combined.AND);
    }

    @Test
    public void findFor_empty() {
        assertThat(Combined.findFor("")).isEqualTo(Combined.OR);
    }

    @Test
    public void fFindFor_null() {
        assertThat(Combined.findFor(null)).isEqualTo(Combined.OR);
    }

    @Test
    public void findFor_something() {

        assertThat(Combined.findFor("X")).isEqualTo(Combined.OR);
    }


}