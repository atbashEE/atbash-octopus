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
package be.atbash.ee.oauth2.sdk.client;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the client credentials parser.
 */
public class ClientCredentialsParserTest {

    @Test
    public void testParseMinimal()
            throws Exception {

        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder();
        jsonObjectBuilder.add("client_id", "123");

        JsonObject jsonObject = jsonObjectBuilder.build();

        assertThat(ClientCredentialsParser.parseID(jsonObject)).isEqualTo(new ClientID("123"));
        assertThat(ClientCredentialsParser.parseIDIssueDate(jsonObject)).isNull();
        assertThat(ClientCredentialsParser.parseSecret(jsonObject)).isNull();
        assertThat(ClientCredentialsParser.parseRegistrationURI(jsonObject)).isNull();
        assertThat(ClientCredentialsParser.parseRegistrationAccessToken(jsonObject)).isNull();
    }

    @Test
    public void testNoIDParseException() {

        Assertions.assertThrows(OAuth2JSONParseException.class, () -> ClientCredentialsParser.parseID(Json.createObjectBuilder().build()));
    }

    @Test
    public void testParseSecretWithNoExpiration()
            throws OAuth2JSONParseException {

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();
        jsonObject.add("client_secret", "secret");

        Secret secret = ClientCredentialsParser.parseSecret(jsonObject.build());

        assertThat(secret.getValue()).isEqualTo("secret");
        assertThat(secret.expired()).isFalse();
    }

    @Test
    public void testParseSecretWithFutureExpiration()
            throws OAuth2JSONParseException {

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();
        jsonObject.add("client_secret", "secret");
        Date futureDate = new Date(new Date().getTime() + 3600 * 1000L);
        jsonObject.add("client_secret_expires_at", futureDate.getTime() / 1000L);

        Secret secret = ClientCredentialsParser.parseSecret(jsonObject.build());
        assertThat(secret.getValue()).isEqualTo("secret");
        assertThat(secret.expired()).isFalse();
        assertThat(secret.getExpirationDate().getTime() / 1000L).isEqualTo(futureDate.getTime() / 1000L);
    }

    @Test
    public void testParseSecretWithPastExpiration()
            throws OAuth2JSONParseException {

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();
        jsonObject.add("client_secret", "secret");
        Date pastDate = new Date(new Date().getTime() - 3600 * 1000L);
        jsonObject.add("client_secret_expires_at", pastDate.getTime() / 1000L);

        Secret secret = ClientCredentialsParser.parseSecret(jsonObject.build());
        assertThat(secret.getValue()).isEqualTo("secret");
        assertThat(secret.expired()).isTrue();
        assertThat(secret.getExpirationDate().getTime() / 1000L).isEqualTo(pastDate.getTime() / 1000L);
    }
}
