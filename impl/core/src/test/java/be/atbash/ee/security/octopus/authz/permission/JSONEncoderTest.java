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

import be.atbash.ee.security.octopus.authz.permission.testclasses.Data;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

public class JSONEncoderTest {

    @Test
    public void customEncoder() {

        Data data = new Data();
        data.setName("Spock");
        List<Permission> permissions = new ArrayList<>();
        permissions.add(new WildcardPermission("domain1:action1:*"));
        permissions.add(new WildcardPermission("domain2:*:*"));
        data.setPermisions(permissions);

        // FIXME
        //assertThat(JSONValue.toJSONString(data)).isEqualTo("{\"permisions\":[\"domain1:action1:*\",\"domain2:*:*\"],\"name\":\"Spock\"}");
    }

    @Test
    public void customDecoder() {

        // FIXME
        //Data data = JSONValue.parse("{\"permisions\":[\"domain1:action1:*\",\"domain2:*:*\"],\"name\":\"Spock\"}", Data.class);

        //assertThat(data.getPermisions()).hasSize(2);
        //assertThat(data.getPermisions().get(0)).isEqualTo(new WildcardPermission("domain1:action1:*"));
        //assertThat(data.getPermisions().get(1)).isEqualTo(new WildcardPermission("domain2:*:*"));
    }
}
