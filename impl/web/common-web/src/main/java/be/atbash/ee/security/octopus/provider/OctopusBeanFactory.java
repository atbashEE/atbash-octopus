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
package be.atbash.ee.security.octopus.provider;

import be.atbash.ee.security.octopus.config.OctopusWebInternalConfiguration;
import be.atbash.ee.security.octopus.util.PatternMatcher;
import be.atbash.util.reflection.ClassUtils;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class OctopusBeanFactory {

    @Inject
    private OctopusWebInternalConfiguration octopusWebInternalConfiguration;

    @Produces
    @ApplicationScoped
    public PatternMatcher createPatternMatcher() {
        String matcherClass = octopusWebInternalConfiguration.getPatternMatcherClass();
        return ClassUtils.newInstance(matcherClass);
    }
}
