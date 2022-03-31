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
package be.atbash.ee.security.rest.view;

import be.atbash.ee.security.rest.HelloService;
import org.eclipse.microprofile.rest.client.inject.RestClient;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.inject.Named;

/**
 *
 */
@RequestScoped
@Named("mpTokenBean")
public class MPTokenBean {

    @Inject
    @RestClient
    private HelloService helloService;

    public void testMPToken() {

        System.out.println("Only authentication " + helloService.sayHello());

        System.out.println("Test authorization " + helloService.testPermission1());
        System.out.println("Test authorization " + helloService.testPermission2());

    }
}
