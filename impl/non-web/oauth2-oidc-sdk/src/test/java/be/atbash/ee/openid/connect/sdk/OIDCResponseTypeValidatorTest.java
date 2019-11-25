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


import be.atbash.ee.oauth2.sdk.ResponseType;
import org.junit.Test;

import static org.junit.Assert.fail;

/**
 * Tests the OIDC response type validator.
 */
public class OIDCResponseTypeValidatorTest {

    @Test
    public void testPass() {

        ResponseType rt = new ResponseType();
        rt.add(ResponseType.Value.CODE);

        OIDCResponseTypeValidator.validate(rt);
    }

    @Test
    public void testEmptyResponseType() {

        ResponseType rt = new ResponseType();

        try {
            OIDCResponseTypeValidator.validate(rt);

            fail("Failed to raise exception");
        } catch (IllegalArgumentException e) {
            // ok
        }
    }

    @Test
    public void testTokenOnlyResponseType() {

        ResponseType rt = new ResponseType();
        rt.add(ResponseType.Value.TOKEN);

        try {
            OIDCResponseTypeValidator.validate(rt);

            fail("Failed to raise exception");
        } catch (IllegalArgumentException e) {
            // ok
        }
    }

    @Test
    public void testUnsupportedResponseType() {

        ResponseType rt = new ResponseType();
        rt.add(new ResponseType.Value("abc"));

        try {
            OIDCResponseTypeValidator.validate(rt);

            fail("Failed to raise exception");
        } catch (IllegalArgumentException e) {
            // ok
        }
    }

    @Test
    public void testCodeTokenIDTokenResponseType() {

        ResponseType rt = new ResponseType();
        rt.add(ResponseType.Value.CODE);
        rt.add(ResponseType.Value.TOKEN);
        rt.add(OIDCResponseTypeValue.ID_TOKEN);

        OIDCResponseTypeValidator.validate(rt);
    }
}