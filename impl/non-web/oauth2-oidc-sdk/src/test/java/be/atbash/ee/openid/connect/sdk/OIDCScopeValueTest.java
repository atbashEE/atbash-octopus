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


import org.junit.Test;

import javax.json.JsonObject;
import javax.json.JsonValue;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the OpenID Connect scope value class.
 */
public class OIDCScopeValueTest {

    @Test
    public void testValues() {

        assertThat(OIDCScopeValue.OPENID.getValue()).isEqualTo("openid");
        assertThat(OIDCScopeValue.PROFILE.getValue()).isEqualTo("profile");
        assertThat(OIDCScopeValue.EMAIL.getValue()).isEqualTo("email");
        assertThat(OIDCScopeValue.ADDRESS.getValue()).isEqualTo("address");
        assertThat(OIDCScopeValue.PHONE.getValue()).isEqualTo("phone");
        assertThat(OIDCScopeValue.OFFLINE_ACCESS.getValue()).isEqualTo("offline_access");

        assertThat(OIDCScopeValue.values().length).isEqualTo(6);
    }

    @Test
    public void testToClaimsRequestJSON() {

        JsonObject o = OIDCScopeValue.OPENID.toClaimsRequestJSONObject();
        assertThat(o.containsKey("sub")).isTrue();
        assertThat(o.getJsonObject("sub").getBoolean("essential")).isTrue();
        assertThat(o).hasSize(1);

        o = OIDCScopeValue.PROFILE.toClaimsRequestJSONObject();
        assertThat(o.containsKey("name")).isTrue();
        assertThat(o.get("name").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("family_name")).isTrue();
        assertThat(o.get("family_name").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("given_name")).isTrue();
        assertThat(o.get("given_name").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("middle_name")).isTrue();
        assertThat(o.get("middle_name").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("nickname")).isTrue();
        assertThat(o.get("nickname").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("preferred_username")).isTrue();
        assertThat(o.get("preferred_username").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("profile")).isTrue();
        assertThat(o.get("profile").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("picture")).isTrue();
        assertThat(o.get("picture").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("website")).isTrue();
        assertThat(o.get("website").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("gender")).isTrue();
        assertThat(o.get("gender").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("birthdate")).isTrue();
        assertThat(o.get("birthdate").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("zoneinfo")).isTrue();
        assertThat(o.get("zoneinfo").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("locale")).isTrue();
        assertThat(o.get("locale").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("updated_at")).isTrue();
        assertThat(o.get("updated_at").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o).hasSize(14);

        o = OIDCScopeValue.EMAIL.toClaimsRequestJSONObject();
        assertThat(o.containsKey("email")).isTrue();
        assertThat(o.get("email").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("email_verified")).isTrue();
        assertThat(o.get("email_verified").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o).hasSize(2);


        o = OIDCScopeValue.ADDRESS.toClaimsRequestJSONObject();
        assertThat(o.containsKey("address")).isTrue();
        assertThat(o.get("address").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o).hasSize(1);

        o = OIDCScopeValue.PHONE.toClaimsRequestJSONObject();
        assertThat(o.containsKey("phone_number")).isTrue();
        assertThat(o.get("phone_number").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o.containsKey("phone_number_verified")).isTrue();
        assertThat(o.get("phone_number_verified").getValueType()).isEqualTo(JsonValue.ValueType.NULL);
        assertThat(o).hasSize(2);

        assertThat(OIDCScopeValue.OFFLINE_ACCESS.toClaimsRequestJSONObject()).isNull();
    }
}
