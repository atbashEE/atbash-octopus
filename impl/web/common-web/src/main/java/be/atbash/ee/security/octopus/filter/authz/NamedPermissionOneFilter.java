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
package be.atbash.ee.security.octopus.filter.authz;

import be.atbash.ee.security.octopus.authz.permission.PermissionResolver;
import be.atbash.ee.security.octopus.subject.WebSubject;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

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
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws
            Exception {
        WebSubject subject = getSubject(request, response);
        String[] permissions = (String[]) mappedValue;

        boolean permitted = false;
        for (String permissionName : permissions) {
            if (subject.isPermitted(permissionResolver.resolvePermission(permissionName))) {
                permitted = true;
            }
        }
        return permitted;
    }

}
