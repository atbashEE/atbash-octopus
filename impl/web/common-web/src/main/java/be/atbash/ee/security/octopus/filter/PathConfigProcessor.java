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
package be.atbash.ee.security.octopus.filter;

import be.atbash.ee.security.octopus.ShiroEquivalent;

import javax.servlet.Filter;

/**
 * A PathConfigProcessor processes configuration entries on a per path (url) basis.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.filter.PathConfigProcessor"})
public interface PathConfigProcessor {
// TODO combine within PathMatchingFilter. All our filters have it!

    /**
     * Processes the specified {@code config}, unique to the given {@code path}, and returns the Filter that should
     * execute for that path/config combination.
     *
     * @param path   the path for which the {@code config} should be applied
     * @param config the configuration for the {@code Filter} specific to the given {@code path}
     * @return the {@code Filter} that should execute for the given path/config combination.
     */
    Filter processPathConfig(String path, String config);
}
