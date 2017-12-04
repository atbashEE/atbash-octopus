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
package be.atbash.ee.security.octopus.web.url;

import be.atbash.ee.security.octopus.Reviewed;
import be.atbash.ee.security.octopus.config.OctopusWebConfiguration;
import be.atbash.ee.security.octopus.exception.OctopusUnexpectedException;
import be.atbash.ee.security.octopus.util.ResourceUtils;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletContext;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Responsible for reading the secured URL info.
 * <p/>
 * Within Shiro/octopus1 it was integrated within the Ini handling. Now it is separate since the Ini is replaced with CDI beans.
 */
@Reviewed
@ApplicationScoped
public class SecuredURLReader {

    @Inject
    private OctopusWebConfiguration octopusWebConfiguration;

    private Map<String, String> urlPatterns;

    public void loadData(ServletContext servletContext) {
        if (urlPatterns != null) {
            // already loaded.
            return;
        }
        urlPatterns = new HashMap<>();
        urlPatterns.putAll(readPatternsFromFile(servletContext));
        urlPatterns.putAll(readPatternsFromCode());
    }

    private Map<String, String> readPatternsFromCode() {
        Map<String, String> result = new HashMap<>();

        List<ProgrammaticURLProtectionProvider> urlProtectionProviders = BeanProvider.getContextualReferences(ProgrammaticURLProtectionProvider.class, true);

        for (ProgrammaticURLProtectionProvider urlProtectionProvider : urlProtectionProviders) {
            result.putAll(urlProtectionProvider.getURLEntriesToAdd());
        }

        return result;
    }

    private Map<String, String> readPatternsFromFile(ServletContext servletContext) {
        Map<String, String> result = new HashMap<>();
        try {
            InputStream inStream = ResourceUtils.getInputStream(servletContext, octopusWebConfiguration.getLocationSecuredURLProperties());
            if (inStream != null) {
                Properties properties = new Properties();
                properties.load(inStream);
                for (String pattern : properties.stringPropertyNames()) {
                    result.put(pattern, properties.getProperty(pattern));
                }
            }
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }
        return result;
    }

    public Map<String, String> getUrlPatterns() {
        return urlPatterns;
    }
}
