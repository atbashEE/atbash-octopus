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
package be.atbash.ee.security.octopus.example;

import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.WildcardPermission;
import be.atbash.ee.security.octopus.token.GenerateOfflineToken;
import be.atbash.ee.security.octopus.token.OfflineToken;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */

public class CreateOfflineTokenFile {

    public static void main(String[] args) throws IOException {
        // Example data
        OfflineToken token = new OfflineToken();
        token.setId("Rudy");
        token.setSubject("rdebusscher");
        token.setName("Rudy De Busscher");

        List<Permission> permissions = new ArrayList<>();
        permissions.add(new WildcardPermission("demo:offline:*"));
        token.setPermissions(permissions);

        String offlineToken = GenerateOfflineToken.createFor(token, "HYa11xOv6_HOwPpxWYnGSLutwvEk3JgbFTa6YED2TyE");

        String fileName = System.getProperty("user.home") + "/octopus.offline.token";
        Writer writer = new FileWriter(fileName);
        writer.write(offlineToken);
        writer.close();

        System.out.println("Offline token written to " + fileName);
    }
}
