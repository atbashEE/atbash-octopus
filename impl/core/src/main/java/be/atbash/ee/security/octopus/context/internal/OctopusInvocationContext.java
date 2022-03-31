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
package be.atbash.ee.security.octopus.context.internal;

import jakarta.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class OctopusInvocationContext {

    private Object target;
    private Method method;
    private Object[] parameters;
    private Map<String, Object> contextData = new HashMap<>();

    public OctopusInvocationContext(Object target, Object[] parameters) {
        this.target = target;
        this.parameters = parameters;
    }

    public OctopusInvocationContext(InvocationContext invocationContext) {
        this.target = invocationContext.getTarget();
        this.method = invocationContext.getMethod();
        this.parameters = invocationContext.getParameters();
    }

    public OctopusInvocationContext(Object target, Method method, Object[] parameters) {
        this.target = target;
        this.method = method;
        this.parameters = parameters;
    }

    public Object getTarget() {
        return target;
    }

    public Method getMethod() {
        return method;
    }

    public Object[] getParameters() {
        return parameters;
    }

    /*
    public void setParameters(Object[] parameters) {
        this.parameters = parameters;
    }
    */

    // FIXME Usage in future to migrate code
    public Map<String, Object> getContextData() {
        return contextData;
    }

    public void addContextData(String key, Object metaData) {
        contextData.put(key, metaData);
    }
}
