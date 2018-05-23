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
package be.atbash.ee.security.octopus.events;

import be.atbash.ee.security.octopus.authc.event.LogonEvent;
import be.atbash.ee.security.octopus.authc.event.LogonFailureEvent;
import be.atbash.ee.security.octopus.authc.event.LogoutEvent;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;

/**
 *
 */
@ApplicationScoped
public class EventLogger {

    public void onSuccess(@Observes LogonEvent logonEvent) {
        System.out.println("xxx onSuccessLogon");
        System.out.println(logonEvent.getInfo());
        System.out.println(logonEvent.getAuthenticationToken());
        System.out.println(logonEvent.getUserPrincipal());
        System.out.println("xxx onSuccessLogon");
    }

    public void onFailure(@Observes LogonFailureEvent logonFailureEvent) {
        System.out.println("xxx onFailureLogon");
        System.out.println(logonFailureEvent.getAuthenticationToken());
        System.out.println(logonFailureEvent.getException());
        System.out.println("xxx onFailureLogon");
    }

    public void onLogout(@Observes LogoutEvent logoutEvent) {
        System.out.println("xxx onLogout");
        System.out.println(logoutEvent.getUserPrincipal());
        System.out.println("xxx onLogout");
    }
}
