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
package be.atbash.ee.security.octopus.util;

import be.atbash.util.ordered.Order;
import be.atbash.util.resource.ResourceReader;

import jakarta.servlet.ServletContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Collections;
import java.util.List;

@Order(20)
public class ServletContextResourceReader implements ResourceReader {
    @Override
    public boolean canRead(String path, Object context) {
        return context instanceof ServletContext;
    }

    @Override
    public boolean exists(String path, Object context) {

        if (!canRead(path, context)) {
            return false;
        }
        try {
            InputStream is = load(path, context);
            boolean result = true;
            if (is == null) {
                result = false;
            } else {
                is.close();
            }
            return result;
        } catch (IOException e) {
            return false;
        }
    }

    @Override
    public InputStream load(String path, Object context) throws IOException {
        InputStream is = null;

        path = WebUtils.normalize(path);
        ServletContext servletContext = (ServletContext) context;
        if (servletContext != null) {
            is = servletContext.getResourceAsStream(path);
        }

        return is;

    }

    @Override
    public List<URI> getResources(String resourcePath) {
        return Collections.emptyList();
    }
}
