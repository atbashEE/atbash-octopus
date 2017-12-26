/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.context;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class OctopusInvocationContext implements InvocationContext {

    private Object target;
    private Object[] parameters;

    public OctopusInvocationContext(Object target, Object[] parameters) {
        this.target = target;
        this.parameters = parameters;
    }

    @Override
    public Object getTarget() {
        return target;
    }

    @Override
    public Object getTimer() {
        // It is ok here to return null
        return null;
    }

    @Override
    public Method getMethod() {
        return null;
    }

    @Override
    public Constructor<?> getConstructor() {
        // FIXME Added in Java EE 7 !!
        return null;
    }

    @Override
    public Object[] getParameters() {
        return parameters;
    }

    @Override
    public void setParameters(Object[] parameters) {
        this.parameters = parameters;
    }

    @Override
    public Map<String, Object> getContextData() {
        return new HashMap<>();
    }

    @Override
    public Object proceed() throws Exception {
        throw new UnsupportedOperationException("OctopusInvocationContext is no real InvocationContext but used for securing JSF Components");
    }
}
