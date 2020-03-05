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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the prompt class.
 */
public class PromptTest {

    @Test
    public void testRun()
            throws Exception {

        Prompt p = new Prompt();
        p.add(Prompt.Type.CONSENT);
        p.add(Prompt.Type.LOGIN);

        assertThat(p.isValid()).isTrue();

        String s = p.toString();

        p = Prompt.parse(s);

        assertThat(p.contains(Prompt.Type.CONSENT)).isTrue();
        assertThat(p.contains(Prompt.Type.LOGIN)).isTrue();
        assertThat(p).hasSize(2);
    }

    @Test
    public void testVarargConstructor() {

        Prompt p = new Prompt(Prompt.Type.LOGIN, Prompt.Type.CONSENT, Prompt.Type.SELECT_ACCOUNT);

        assertThat(p.contains(Prompt.Type.LOGIN)).isTrue();
        assertThat(p.contains(Prompt.Type.CONSENT)).isTrue();
        assertThat(p.contains(Prompt.Type.SELECT_ACCOUNT)).isTrue();

        assertThat(p).hasSize(3);

        assertThat(p.isValid()).isTrue();
    }

    @Test
    public void testVarargStringConstructor() {

        Prompt p = new Prompt("login", "consent", "select_account");

        assertThat(p.contains(Prompt.Type.LOGIN)).isTrue();
        assertThat(p.contains(Prompt.Type.CONSENT)).isTrue();
        assertThat(p.contains(Prompt.Type.SELECT_ACCOUNT)).isTrue();

        assertThat(p).hasSize(3);

        assertThat(p.isValid()).isTrue();
    }

    @Test
    public void testListSerializationAndParsing()
            throws Exception {

        Prompt p = new Prompt();
        p.add(Prompt.Type.CONSENT);
        p.add(Prompt.Type.LOGIN);

        assertThat(p.isValid()).isTrue();

        List<String> list = p.toStringList();

        assertThat(list.contains("consent")).isTrue();
        assertThat(list.contains("login")).isTrue();
        assertThat(list).hasSize(2);

        p = Prompt.parse(list);

        assertThat(p.contains(Prompt.Type.CONSENT)).isTrue();
        assertThat(p.contains(Prompt.Type.LOGIN)).isTrue();
        assertThat(p).hasSize(2);
    }

    @Test
    public void testParseInvalidPrompt() {

        Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                Prompt.parse("none login"));

        Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                Prompt.parse("none consent"));


        Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                Prompt.parse("none select_account"));


        Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                Prompt.parse("none login consent select_account"));

    }
}
