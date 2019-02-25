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
package be.atbash.ee.security.octopus.async;


import be.atbash.ee.security.octopus.context.OctopusSecurityContext;
import be.atbash.ee.security.octopus.systemaccount.SystemAccount;

import javax.annotation.security.PermitAll;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.inject.Inject;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 *
 */
@Stateless
@PermitAll
public class DemoService {

    @Inject
    private WorkerService workerService;

    @Inject
    private OctopusSecurityContext octopusSecurityContext;

    public String sayHello() throws Exception {
        //octopusSecurityContext.prepareForAsyncUsage();

        Future<String> stringFuture = workerService.doInBackground();
        String result = null;
        try {
            result = stringFuture.get(500L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            if (e.getCause() instanceof EJBException) {
                throw ((EJBException) e.getCause()).getCausedByException();
            }
            e.printStackTrace();
        } catch (TimeoutException e) {
            e.printStackTrace();
        }
        return result;
    }

    @SystemAccount("Demo")
    public String fromMachine() {
        return "Hello from system account authenticated protected method";
    }
}
