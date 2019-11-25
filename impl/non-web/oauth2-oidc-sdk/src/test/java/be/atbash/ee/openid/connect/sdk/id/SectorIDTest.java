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
package be.atbash.ee.openid.connect.sdk.id;


import org.junit.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class SectorIDTest {

    @Test
    public void testStringConstructor() {

        SectorID sectorID = new SectorID("example.com");
        assertThat(sectorID.getValue()).isEqualTo("example.com");
    }

    @Test
    public void testURIConstructor() {

        SectorID sectorID = new SectorID(URI.create("https://example.com"));
        assertThat(sectorID.getValue()).isEqualTo("example.com");
    }

    @Test
    public void testURIConstructor_missingHost() {

        try {
            new SectorID(URI.create("https:///path/a/b/c"));
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The URI must contain a host component");
        }
    }

    @Test
    public void testEnsureHTTPScheme() {

        try {
            SectorID.ensureHTTPScheme(URI.create("http://example.com/callbacks.json"));
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The URI must have a https scheme");
        }
    }
}
