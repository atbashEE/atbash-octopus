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
package be.atbash.ee.security.octopus.util;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;
import java.io.IOException;
import java.io.InputStream;

import static be.atbash.config.util.ResourceUtils.*;

/**
 * Static helper methods for loading {@code Stream}-backed resources.
 *
 * @see #getInputStreamForPath(String)
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.io.ResourceUtils"})
public class ResourceUtils {

    /**
     * Private internal log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(ResourceUtils.class);

    /**
     * Prevent instantiation.
     */
    private ResourceUtils() {
    }

    /**
     * Returns {@code true} if the resource path is not null and starts with one of the recognized
     * resource prefixes ({@link #CLASSPATH_PREFIX CLASSPATH_PREFIX},
     * {@link #URL_PREFIX URL_PREFIX}, or {@link #FILE_PREFIX FILE_PREFIX}), {@code false} otherwise.
     *
     * @param resourcePath the resource path to check
     * @return {@code true} if the resource path is not null and starts with one of the recognized
     * resource prefixes, {@code false} otherwise.
     */
    @SuppressWarnings({"UnusedDeclaration"})
    public static boolean hasResourcePrefix(String resourcePath) {
        return resourcePath != null &&
                (resourcePath.startsWith(CLASSPATH_PREFIX) ||
                        resourcePath.startsWith(URL_PREFIX) ||
                        resourcePath.startsWith(FILE_PREFIX));
    }

    public static InputStream getInputStream(ServletContext context, String path) throws IOException {
        // FIXME Refactor in resource API
        InputStream result = null;
        if (StringUtils.hasText(path)) {

            if (!hasResourcePrefix(path)) {
                result = getServletContextResourceStream(context, path);
            } else {
                try {
                    result = getInputStreamForPath(path);
                } catch (IOException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Unable to load optional path '" + path + "'.", e);
                    }
                }
            }

        }
        return result;

    }

    //TODO - this logic is ugly - it'd be ideal if we had a Resource API to polymorphically encaspulate this behavior
    private static InputStream getServletContextResourceStream(ServletContext servletContext, String path) {
        InputStream is = null;

        path = WebUtils.normalize(path);
        if (servletContext != null) {
            is = servletContext.getResourceAsStream(path);
        }

        return is;
    }

}
