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
package be.atbash.ee.security.octopus.web.servlet;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.util.Nameable;
import be.atbash.util.Reviewed;

import java.util.HashSet;
import java.util.Set;

/**
 * Allows a filter to be named. A filter has a 'main' name and possibly multiple aliases.
 * All 'Octopus' Filters should be CDI beans and the name should be set within a @PostConstruct annotated initialization method.
 */
@Reviewed
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.servlet.NameableFilter"})
public abstract class NameableFilter extends AbstractFilter implements Nameable {

    /**
     * The name(s) of this filter, unique within an application.
     */
    private Set<String> names = new HashSet<>();

    /**
     * The First name assigned to this filter.
     */
    private String name;

    /**
     * Returns the filter's name and aliases.
     * <p/>
     *
     * @return the filter name and aliases, or {@code empty} collection if none available.
     */
    public Set<String> getNames() {
        return names;
    }

    /**
     * Sets the filter's name.
     * <p/>
     * Unless overridden by calling this method, this value defaults to the filter name as specified by the
     * servlet container at start-up:
     * <pre>
     *
     * @param name the name of the filter.
     */
    public void setName(String name) {
        if (names.isEmpty()) {
            this.name = name;
        }
        names.add(name);
    }

    /**
     * Returns the name of the filter not taking into account the aliases.
     *
     * @return Name of the filter.
     */
    public String getName() {
        return name;
    }

    /**
     * Returns a StringBuilder instance with the {@link #getNames() name and aliases}, or if the name is {@code null}, just the
     * {@code super.toStringBuilder()} instance.
     *
     * @return a StringBuilder instance to use for appending String data that will eventually be returned from a
     * {@code toString()} invocation.
     */
    protected StringBuilder toStringBuilder() {
        String name = defineName();
        if (name == null) {
            return new StringBuilder(this.getClass().getName());
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append(name);
            return sb;
        }
    }

    private String defineName() {
        StringBuilder result = new StringBuilder();
        for (String name : names) {
            if (result.length() > 0) {
                result.append(", ");
            }
            result.append(name);
        }

        if (result.length() > 0) {
            return result.toString();
        } else {
            return null;
        }

    }

}
