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


import be.atbash.ee.security.octopus.authz.annotation.RequiresUser;
import be.atbash.ee.security.octopus.subject.UserPrincipal;

import javax.ejb.AsyncResult;
import javax.ejb.Asynchronous;
import javax.ejb.Stateless;
import javax.inject.Inject;
import java.util.concurrent.Future;

/**
 *
 */
@Stateless
@RequiresUser
public class WorkerService {

    @Inject
    private UserPrincipal userPrincipal;

    @Asynchronous
    public Future<String> doInBackground() {
        try {
            Thread.sleep(100L);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return new AsyncResult<>("Hello Async World : " + userPrincipal.getName());
    }
}
