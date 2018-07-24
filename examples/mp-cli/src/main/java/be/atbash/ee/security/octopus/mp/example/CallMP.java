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
package be.atbash.ee.security.octopus.mp.example;

import be.atbash.ee.security.octopus.context.OctopusSecurityContext;
import be.atbash.ee.security.octopus.mp.exception.UnauthorizedExceptionMapper;
import be.atbash.ee.security.octopus.mp.rest.MPRestClientProvider;
import be.atbash.ee.security.octopus.token.OfflineToken;
import be.atbash.ee.security.octopus.token.OfflineTokenParser;
import org.eclipse.microprofile.rest.client.AbstractRestClientBuilder;

import java.net.MalformedURLException;
import java.net.URL;

/**
 *
 */

public class CallMP {

    public static void main(String[] args) throws MalformedURLException {
        // tokenEncoded should be taken from <user_home>/octopus.offline.token and generated by CreateOfflineTokenFile
        String tokenEncoded = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsIk9jdG9wdXMgT2ZmbGluZSI6InYwLjIiLCJraWQiOiJsb2NhbCBzZWNyZXQifQ.eyJzdWJqZWN0IjoicmRlYnVzc2NoZXIiLCJwZXJtaXNzaW9ucyI6WyJkZW1vOm9mZmxpbmU6KiJdLCJuYW1lIjoiUnVkeSBEZSBCdXNzY2hlciIsImlkIjoiUnVkeSJ9.Lfiq_PeDW7LNxftnTQk-L_wGYn5diD-lRnOqFtB2mZ0";
        String passPhrase = "Rudy";

        OfflineToken token = OfflineTokenParser.parse(tokenEncoded, passPhrase);
        OctopusSecurityContext.getInstance().authenticate(token);

        HelloService helloService = AbstractRestClientBuilder.newBuilder()
                .baseUrl(new URL("http://localhost:8080/rest-mp/data"))
                .register(MPRestClientProvider.class)
                .register(UnauthorizedExceptionMapper.class)
                .build(HelloService.class);

        System.out.println(helloService.sayHello());

        System.out.println(helloService.testPermission1());
    }
}