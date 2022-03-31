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
package be.atbash.ee.security.octopus.filter.authz;

import be.atbash.ee.security.octopus.authz.permission.PermissionResolver;
import be.atbash.ee.security.octopus.subject.WebSubject;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

@ApplicationScoped
public class NamedPermissionOneFilter extends AuthorizationFilter {

    @Inject
    private PermissionResolver permissionResolver;

    @PostConstruct
    public void initInstance() {
        setName("np1");
        setName("namedPermission1");
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response) throws
            Exception {
        WebSubject subject = getSubject();

        String[] pathConfig = getPathConfig(request);

        boolean permitted = false;
        for (String permissionName : pathConfig) {
            if (subject.isPermitted(permissionResolver.resolvePermission(permissionName))) {
                permitted = true;
            }
        }
        return permitted;
    }

    @Override
    protected boolean requiresPathConfiguration() {
        return true;
    }

}
