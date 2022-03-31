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
package be.atbash.ee.openid.connect.sdk.claims;


import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.jupiter.api.Test;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


public class ExternalClaimsUtilsTest {

    // getExternalClaimSources
    @Test
    public void testGetExternalClaimSources_specAggregatedExample()
            throws Exception {

        String json =
                "{" +
                        "   \"name\": \"Jane Doe\"," +
                        "   \"given_name\": \"Jane\"," +
                        "   \"family_name\": \"Doe\"," +
                        "   \"birthdate\": \"0000-03-22\"," +
                        "   \"eye_color\": \"blue\"," +
                        "   \"email\": \"janedoe@example.com\"," +
                        "   \"_claim_names\": {" +
                        "     \"address\": \"src1\"," +
                        "     \"phone_number\": \"src1\"" +
                        "   }," +
                        "   \"_claim_sources\": {" +
                        "     \"src1\": {\"JWT\": \"jwt_header.jwt_part2.jwt_part3\"}" +
                        "   }" +
                        "  }";

        JsonObject jsonObject = JSONObjectUtils.parse(json);

        Map<String, JsonObject> ext = ExternalClaimsUtils.getExternalClaimSources(jsonObject);

        JsonObject sourceSpec = ext.get("src1");
        assertThat(sourceSpec.getString("JWT")).isEqualTo("jwt_header.jwt_part2.jwt_part3");
        assertThat(sourceSpec).hasSize(1);

        assertThat(ext).hasSize(1);
    }

    @Test
    public void testGetExternalClaimSources_specDistributedExample()
            throws Exception {

        String json =
                "{\n" +
                        "   \"name\": \"Jane Doe\",\n" +
                        "   \"given_name\": \"Jane\",\n" +
                        "   \"family_name\": \"Doe\",\n" +
                        "   \"email\": \"janedoe@example.com\",\n" +
                        "   \"birthdate\": \"0000-03-22\",\n" +
                        "   \"eye_color\": \"blue\",\n" +
                        "   \"_claim_names\": {\n" +
                        "     \"payment_info\": \"src1\",\n" +
                        "     \"shipping_address\": \"src1\",\n" +
                        "     \"credit_score\": \"src2\"\n" +
                        "    },\n" +
                        "   \"_claim_sources\": {\n" +
                        "     \"src1\": {\"endpoint\":\n" +
                        "                \"https://bank.example.com/claim_source\"},\n" +
                        "     \"src2\": {\"endpoint\":\n" +
                        "                \"https://creditagency.example.com/claims_here\",\n" +
                        "              \"access_token\": \"ksj3n283dke\"}\n" +
                        "   }\n" +
                        "  }";

        JsonObject jsonObject = JSONObjectUtils.parse(json);

        Map<String, JsonObject> ext = ExternalClaimsUtils.getExternalClaimSources(jsonObject);

        JsonObject sourceSpec1 = ext.get("src1");
        assertThat(sourceSpec1.getString("endpoint")).isEqualTo("https://bank.example.com/claim_source");
        assertThat(sourceSpec1).hasSize(1);

        JsonObject sourceSpec2 = ext.get("src2");
        assertThat(sourceSpec2.getString("endpoint")).isEqualTo("https://creditagency.example.com/claims_here");
        assertThat(sourceSpec2.getString("access_token")).isEqualTo("ksj3n283dke");

        assertThat(ext).hasSize(2);
    }

    @Test
    public void testGetExternalClaimSources_none() {

        assertThat(ExternalClaimsUtils.getExternalClaimSources(Json.createObjectBuilder().build())).isNull();
    }

    @Test
    public void testGetExternalClaimSources_empty() {

        JsonObjectBuilder jsonObjectbuilder = Json.createObjectBuilder();
        jsonObjectbuilder.add("_claim_sources", Json.createObjectBuilder().build());

        assertThat(ExternalClaimsUtils.getExternalClaimSources(jsonObjectbuilder.build())).isNull();
    }

    @Test
    public void testGetExternalClaimSources_invalidSpec() {

        JsonObjectBuilder jsonObjectbuilder = Json.createObjectBuilder();
        JsonObjectBuilder claimSourcesbuilder = Json.createObjectBuilder();
        claimSourcesbuilder.add("src1", "invalid");
        jsonObjectbuilder.add("_claim_sources", claimSourcesbuilder.build());

        assertThat(ExternalClaimsUtils.getExternalClaimSources(jsonObjectbuilder.build())).isNull();
    }


    // getExternalClaimNamesForSource
    @Test
    public void testGetExternalClaimNamesForSource_specAggregatedExample()
            throws Exception {

        String json =
                "{" +
                        "   \"name\": \"Jane Doe\"," +
                        "   \"given_name\": \"Jane\"," +
                        "   \"family_name\": \"Doe\"," +
                        "   \"birthdate\": \"0000-03-22\"," +
                        "   \"eye_color\": \"blue\"," +
                        "   \"email\": \"janedoe@example.com\"," +
                        "   \"_claim_names\": {" +
                        "     \"address\": \"src1\"," +
                        "     \"phone_number\": \"src1\"" +
                        "   }," +
                        "   \"_claim_sources\": {" +
                        "     \"src1\": {\"JWT\": \"jwt_header.jwt_part2.jwt_part3\"}" +
                        "   }" +
                        "  }";

        JsonObject jsonObject = JSONObjectUtils.parse(json);

        Set<String> names = ExternalClaimsUtils.getExternalClaimNamesForSource(jsonObject, "src1");
        assertThat(names.contains("address")).isTrue();
        assertThat(names.contains("phone_number")).isTrue();
        assertThat(names).hasSize(2);
    }

    @Test
    public void testGetExternalClaimNamesForSource_specDistributedExample()
            throws Exception {

        String json =
                "{\n" +
                        "   \"name\": \"Jane Doe\",\n" +
                        "   \"given_name\": \"Jane\",\n" +
                        "   \"family_name\": \"Doe\",\n" +
                        "   \"email\": \"janedoe@example.com\",\n" +
                        "   \"birthdate\": \"0000-03-22\",\n" +
                        "   \"eye_color\": \"blue\",\n" +
                        "   \"_claim_names\": {\n" +
                        "     \"payment_info\": \"src1\",\n" +
                        "     \"shipping_address\": \"src1\",\n" +
                        "     \"credit_score\": \"src2\"\n" +
                        "    },\n" +
                        "   \"_claim_sources\": {\n" +
                        "     \"src1\": {\"endpoint\":\n" +
                        "                \"https://bank.example.com/claim_source\"},\n" +
                        "     \"src2\": {\"endpoint\":\n" +
                        "                \"https://creditagency.example.com/claims_here\",\n" +
                        "              \"access_token\": \"ksj3n283dke\"}\n" +
                        "   }\n" +
                        "  }";

        JsonObject jsonObject = JSONObjectUtils.parse(json);

        Set<String> names = ExternalClaimsUtils.getExternalClaimNamesForSource(jsonObject, "src1");
        assertThat(names.contains("payment_info")).isTrue();
        assertThat(names.contains("shipping_address")).isTrue();
        assertThat(names).hasSize(2);

        names = ExternalClaimsUtils.getExternalClaimNamesForSource(jsonObject, "src2");
        assertThat(names.contains("credit_score")).isTrue();
        assertThat(names).hasSize(1);

        // Source not present
        assertThat(ExternalClaimsUtils.getExternalClaimNamesForSource(jsonObject, "no-such-source").isEmpty()).isTrue();
    }

    @Test
    public void testGetExternalClaimNamesForSource_none() {

        assertThat(ExternalClaimsUtils.getExternalClaimNamesForSource(Json.createObjectBuilder().build(), "src1").isEmpty()).isTrue();
    }

    @Test
    public void testGetExternalClaimNamesForSource_ignoreNullSourceID() {

        JsonObjectBuilder claimsbuilder = Json.createObjectBuilder();
        JsonObjectBuilder extClaimNamesbuilder = Json.createObjectBuilder();
        extClaimNamesbuilder.addNull("payment_info");
        claimsbuilder.add("_claim_names", extClaimNamesbuilder.build());

        assertThat(ExternalClaimsUtils.getExternalClaimNamesForSource(claimsbuilder.build(), "src1").isEmpty()).isTrue();
    }

    @Test
    public void testGetExternalClaimNamesForSource_ignoreNonStringSourceID() {

        JsonObjectBuilder claimsbuilder = Json.createObjectBuilder();
        JsonObjectBuilder extClaimNamesbuilder = Json.createObjectBuilder();
        extClaimNamesbuilder.add("payment_info", 100);
        claimsbuilder.add("_claim_names", extClaimNamesbuilder.build());

        assertThat(ExternalClaimsUtils.getExternalClaimNamesForSource(claimsbuilder.build(), "src1").isEmpty()).isTrue();
    }
}
