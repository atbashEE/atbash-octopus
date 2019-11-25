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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the Display class.
 */
public class DisplayTest {

    @Test
    public void testToString() {

        assertThat(Display.PAGE.toString()).isEqualTo("page");
        assertThat(Display.POPUP.toString()).isEqualTo("popup");
        assertThat(Display.TOUCH.toString()).isEqualTo("touch");
        assertThat(Display.WAP.toString()).isEqualTo("wap");
    }

    @Test
    public void testDefault() {

        assertThat(Display.getDefault()).isEqualTo(Display.PAGE);
    }

    @Test
    public void testParsePage()
            throws OAuth2JSONParseException {

        assertThat(Display.parse("page")).isEqualTo(Display.PAGE);
    }

    @Test
    public void testParsePopup()
            throws OAuth2JSONParseException {

        assertThat(Display.parse("popup")).isEqualTo(Display.POPUP);
    }

    @Test
    public void testParseTouch()
            throws OAuth2JSONParseException {

        assertThat(Display.parse("touch")).isEqualTo(Display.TOUCH);
    }

    @Test
    public void testParseWap()
            throws OAuth2JSONParseException {

        assertThat(Display.parse("wap")).isEqualTo(Display.WAP);
    }

    @Test
    public void testParseNull()
            throws OAuth2JSONParseException {

        assertThat(Display.parse(null)).isEqualTo(Display.PAGE);
    }

    @Test
    public void testParseEmptyString()
            throws OAuth2JSONParseException {

        assertThat(Display.parse("")).isEqualTo(Display.PAGE);
    }

    @Test
    public void testParseException() {

        try {
            Display.parse("some-unsupported-display-type");

            fail("Failed to throw parse exception");

        } catch (OAuth2JSONParseException e) {
            // ok
        }
    }
}