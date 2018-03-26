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
package be.atbash.ee.security.octopus.web.url;

import be.atbash.ee.security.octopus.config.OctopusWebConfiguration;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.util.ResourceUtils;
import be.atbash.util.CDIUtils;
import be.atbash.util.Reviewed;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletContext;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

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
        urlPatterns = new LinkedHashMap<>();
        // Patterns from code should become first so that we can always enforce some protection defined within modules
        urlPatterns.putAll(readPatternsFromCode());
        urlPatterns.putAll(readPatternsFromFile(servletContext));
    }

    private Map<String, String> readPatternsFromCode() {
        Map<String, String> result = new LinkedHashMap<>();

        List<ProgrammaticURLProtectionProvider> urlProtectionProviders = CDIUtils.retrieveInstances(ProgrammaticURLProtectionProvider.class);

        for (ProgrammaticURLProtectionProvider urlProtectionProvider : urlProtectionProviders) {
            result.putAll(urlProtectionProvider.getURLEntriesToAdd());
        }

        return result;
    }

    private Map<String, String> readPatternsFromFile(ServletContext servletContext) {
        Map<String, String> result = new LinkedHashMap<>();
        try {

            InputStream inStream = ResourceUtils.getInputStream(servletContext, octopusWebConfiguration.getLocationSecuredURLProperties());
            if (inStream != null) {
                List<String> lines = readFile(inStream);

                for (String line : lines) {
                    String trimmedLine = line.trim();
                    if (!trimmedLine.isEmpty() && !trimmedLine.startsWith("#")) {
                        String[] parts = trimmedLine.split("=", 2);
                        if (parts.length == 2) {
                            result.put(parts[0].trim(), parts[1].trim());
                        } else {
                            throw new ConfigurationException(String.format("Wrong line within %s file -> %s", octopusWebConfiguration.getLocationSecuredURLProperties(), trimmedLine));
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }
        return result;
    }

    private List<String> readFile(InputStream inStream) {
        List<String> result = new ArrayList<>();
        Scanner scanner = new Scanner(inStream);
        while (scanner.hasNextLine()) {
            result.add(scanner.nextLine());
        }
        scanner.close();
        return result;
    }

    public Map<String, String> getUrlPatterns() {
        return urlPatterns;
    }
}
