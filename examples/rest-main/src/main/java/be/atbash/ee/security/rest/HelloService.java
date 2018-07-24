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
package be.atbash.ee.security.rest;

import be.atbash.ee.security.octopus.mp.exception.UnauthorizedExceptionMapper;
import be.atbash.ee.security.octopus.mp.rest.MPRestClientProvider;
import org.eclipse.microprofile.rest.client.annotation.RegisterProvider;
import org.eclipse.microprofile.rest.client.annotation.RegisterProviders;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

@Path("/hello")
@ApplicationScoped
@RegisterRestClient
@RegisterProviders({@RegisterProvider(MPRestClientProvider.class), @RegisterProvider(UnauthorizedExceptionMapper.class)})
// FIXME Use Feature and add UnauthorizedExceptionMapper dynamically (or new module
public interface HelloService {

    @GET
    String sayHello();

    @Path("/protectedPermission1")
    @GET
    String testPermission1();

    @Path("/protectedPermission2")
    @GET
    String testPermission2();

}