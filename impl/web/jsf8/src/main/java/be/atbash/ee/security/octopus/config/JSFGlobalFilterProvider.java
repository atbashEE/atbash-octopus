/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.config;

import be.atbash.ee.security.octopus.filter.GlobalFilterProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class JSFGlobalFilterProvider implements GlobalFilterProvider {

    @Inject
    private OctopusJSFConfiguration jsfConfiguration;

    private List<String> filters;

    @PostConstruct
    public void init() {
        filters = new ArrayList<>();
        filters.add("sh");
    }

    @Override
    public List<String> addFiltersTo(String url) {
        if (jsfConfiguration.getSessionHijackingLevel() != SessionHijackingLevel.OFF) {
            return filters;
        } else {
            return Collections.emptyList();
        }
    }
}
