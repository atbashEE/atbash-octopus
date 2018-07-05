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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 * When an AuthorizationFilter detects that the user is unauthorized, this handler performs the actions.
 * This interface exists to be able to separate the actions for JAX-RS and JSF.
 */
// FIXME When application has JSF and JAX-RS -> both handlers are found and thus deployment issue.
//So we need another level and based on the fact if we noSessionCreation filter -> use Rest or Jsf handler.
public interface AccessDeniedHandler {

    /**
     * Processes requests where the subject was denied access as determined by the
     * {@link be.atbash.ee.security.octopus.filter.AccessControlFilter.isAccessAllowed(ServletRequest, ServletResponse, Object) isAccessAllowed}
     * method.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return <code>true</code> if the request should continue to be processed; false if the subclass will
     * handle/render the response directly.
     * @throws Exception if there is an error processing the request.
     */
    boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException;
    // TODO Support for MappedValue ??
}
