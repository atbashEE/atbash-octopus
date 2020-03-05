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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class WildcardPermissionTest {

    @Test
    public void constructorNull() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new WildcardPermission(null));
    }

    @Test
    public void constructorEmpty() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new WildcardPermission(""));
    }

    @Test
    public void constructorBlank() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new WildcardPermission("   "));
    }

    @Test
    public void onlyDelimiters() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new WildcardPermission("::,,::,:"));
    }

    @Test
    public void testNamed() {
        WildcardPermission p1, p2;

        // Case insensitive, same
        p1 = new WildcardPermission("something");
        p2 = new WildcardPermission("something");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isTrue();

        // Case insensitive, different case
        p1 = new WildcardPermission("something");
        p2 = new WildcardPermission("SOMETHING");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isTrue();

        // Case insensitive, different word
        p1 = new WildcardPermission("something");
        p2 = new WildcardPermission("else");
        assertThat(p1.implies(p2)).isFalse();
        assertThat(p2.implies(p1)).isFalse();

        // Case sensitive same
        p1 = new WildcardPermission("BLAHBLAH", true);
        p2 = new WildcardPermission("BLAHBLAH", true);
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isTrue();

        // Case sensitive, different case
        p1 = new WildcardPermission("BLAHBLAH", true);
        p2 = new WildcardPermission("bLAHBLAH", true);
        assertThat(p1.implies(p2)).isFalse();
        assertThat(p2.implies(p1)).isFalse();

        // Case sensitive, different word
        p1 = new WildcardPermission("BLAHBLAH", true);
        p2 = new WildcardPermission("whatwhat", true);
        assertThat(p1.implies(p2)).isFalse();
        assertThat(p2.implies(p1)).isFalse();

    }

    @Test
    public void testLists() {
        WildcardPermission p1, p2, p3;

        p1 = new WildcardPermission("one,two");
        p2 = new WildcardPermission("one");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isFalse();

        p1 = new WildcardPermission("one,two,three");
        p2 = new WildcardPermission("one,three");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isFalse();

        p1 = new WildcardPermission("one,two:one,two,three");
        p2 = new WildcardPermission("one:three");
        p3 = new WildcardPermission("one:two,three");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isFalse();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p2.implies(p3)).isFalse();
        assertThat(p3.implies(p2)).isTrue();

        p1 = new WildcardPermission("one,two,three:one,two,three:one,two");
        p2 = new WildcardPermission("one:three:two");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isFalse();

        p1 = new WildcardPermission("one");
        p2 = new WildcardPermission("one:two,three,four");
        p3 = new WildcardPermission("one:two,three,four:five:six:seven");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p2.implies(p1)).isFalse();
        assertThat(p3.implies(p1)).isFalse();
        assertThat(p2.implies(p3)).isTrue();
    }

    /**
     * Validates WildcardPermissions with that contain the same list parts are equal.
     */
    @Test
    public void listDifferentOrder() {

        WildcardPermission p6 = new WildcardPermission("one,two:three,four");
        WildcardPermission p6DiffOrder = new WildcardPermission("two,one:four,three");
        assertThat(p6.equals(p6DiffOrder)).isTrue();
    }

    /**
     * Validates WildcardPermissions with that contain the same list parts are equal.
     */
    @Test
    public void trimsValues() {
        WildcardPermission p1, p2;
        p1 = new WildcardPermission("newsletter:*");
        p2 = new WildcardPermission("newsletter : read");

        assertThat(p1.implies(p2)).isTrue();
        assertThat(p2.implies(p1)).isFalse();

        // Verify domain
        assertThat(p2.getParts().get(0)).containsOnly("newsletter");

        // Verify actions
        assertThat(p2.getParts().get(1)).containsOnly("read");

        // Verify targets
        assertThat(p2.getParts()).hasSize(2);

    }

    @Test
    public void testWildcards() {
        WildcardPermission p1, p2, p3, p4, p5, p6, p7, p8;

        p1 = new WildcardPermission("*");
        p2 = new WildcardPermission("one");
        p3 = new WildcardPermission("one:two");
        p4 = new WildcardPermission("one,two:three,four");
        p5 = new WildcardPermission("one,two:three,four,five:six:seven,eight");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p1.implies(p4)).isTrue();
        assertThat(p1.implies(p5)).isTrue();

        p1 = new WildcardPermission("newsletter:*");
        p2 = new WildcardPermission("newsletter:read");
        p3 = new WildcardPermission("newsletter:read,write");
        p4 = new WildcardPermission("newsletter:*");
        p5 = new WildcardPermission("newsletter:*:*");
        p6 = new WildcardPermission("newsletter:*:read");
        p7 = new WildcardPermission("newsletter:write:*");
        p8 = new WildcardPermission("newsletter:read,write:*");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p1.implies(p4)).isTrue();
        assertThat(p1.implies(p5)).isTrue();
        assertThat(p1.implies(p6)).isTrue();
        assertThat(p1.implies(p7)).isTrue();
        assertThat(p1.implies(p8)).isTrue();

        p1 = new WildcardPermission("newsletter:*:*");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p1.implies(p4)).isTrue();
        assertThat(p1.implies(p5)).isTrue();
        assertThat(p1.implies(p6)).isTrue();
        assertThat(p1.implies(p7)).isTrue();
        assertThat(p1.implies(p8)).isTrue();

        p1 = new WildcardPermission("newsletter:*:*:*");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isTrue();
        assertThat(p1.implies(p4)).isTrue();
        assertThat(p1.implies(p5)).isTrue();
        assertThat(p1.implies(p6)).isTrue();
        assertThat(p1.implies(p7)).isTrue();
        assertThat(p1.implies(p8)).isTrue();

        p1 = new WildcardPermission("newsletter:*:read");
        p2 = new WildcardPermission("newsletter:123:read");
        p3 = new WildcardPermission("newsletter:123,456:read,write");
        p4 = new WildcardPermission("newsletter:read");
        p5 = new WildcardPermission("newsletter:read,write");
        p6 = new WildcardPermission("newsletter:123:read:write");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p3)).isFalse();
        assertThat(p1.implies(p4)).isFalse();
        assertThat(p1.implies(p5)).isFalse();
        assertThat(p1.implies(p6)).isTrue();

        p1 = new WildcardPermission("newsletter:*:read:*");
        assertThat(p1.implies(p2)).isTrue();
        assertThat(p1.implies(p6)).isTrue();

    }

    @Test
    public void testToString() {
        WildcardPermission p1 = new WildcardPermission("*");
        WildcardPermission p2 = new WildcardPermission("one");
        WildcardPermission p3 = new WildcardPermission("one:two");
        WildcardPermission p4 = new WildcardPermission("one,two:three,four");
        WildcardPermission p5 = new WildcardPermission("one,two:three,four,five:six:seven,eight");

        assertThat("*".equals(p1.toString())).isTrue();
        assertThat(p1.equals(new WildcardPermission(p1.toString()))).isTrue();
        assertThat("one".equals(p2.toString())).isTrue();
        assertThat(p2.equals(new WildcardPermission(p2.toString()))).isTrue();
        assertThat("one:two".equals(p3.toString())).isTrue();
        assertThat(p3.equals(new WildcardPermission(p3.toString()))).isTrue();
        assertThat("one,two:three,four".equals(p4.toString())).isTrue();
        assertThat(p4.equals(new WildcardPermission(p4.toString()))).isTrue();
        assertThat("one,two:three,four,five:six:seven,eight".equals(p5.toString())).isTrue();
        assertThat(p5.equals(new WildcardPermission(p5.toString()))).isTrue();
    }
}