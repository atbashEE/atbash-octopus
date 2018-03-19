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

import be.atbash.ee.security.octopus.authz.permission.voter.AbstractGenericVoter;
import be.atbash.ee.security.octopus.context.internal.OctopusInvocationContext;
import be.atbash.ee.security.octopus.interceptor.CustomAccessDecisionVoterContext;
import be.atbash.util.CDIUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
public class CustomVoterFilter extends AuthorizationFilter {

    @PostConstruct
    public void initInstance() {
        setName("voter");
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {

        String[] voters = (String[]) mappedValue;

        String url = ((HttpServletRequest) request).getRequestURL().toString();

        OctopusInvocationContext invocationContext = new OctopusInvocationContext(url, new Object[]{request});
        AccessDecisionVoterContext context = new CustomAccessDecisionVoterContext(invocationContext);

        boolean permitted = true;

        for (String voter : voters) {
            AbstractGenericVoter voterObj = CDIUtils.retrieveInstanceByName(voter, AbstractGenericVoter.class);
            if (!voterObj.verify(context)) {
                permitted = false;
                break;
            }
        }
        return permitted;
    }
}
