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
package be.atbash.ee.security.octopus.util;


import be.atbash.ee.security.octopus.Reviewed;
import be.atbash.ee.security.octopus.ShiroEquivalent;

/**
 * Interface implemented by components that can be named, such as via configuration, and wish to have that name
 * set once it has been configured.
 *
 */
@Reviewed
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.util.Nameable"})
public interface Nameable {

    /**
     * Sets the (preferably application unique) name for this component.
     *
     * @param name the preferably application unique name for this component.
     */
    void setName(String name);
}
