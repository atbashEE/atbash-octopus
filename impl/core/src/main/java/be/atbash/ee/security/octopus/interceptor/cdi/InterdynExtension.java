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
package be.atbash.ee.security.octopus.interceptor.cdi;

import be.atbash.ee.security.octopus.authc.AuthenticationInfoProvider;
import be.atbash.ee.security.octopus.authz.AuthorizationInfoProvider;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.interceptor.OctopusInterceptorBinding;
import be.atbash.util.exception.AtbashUnexpectedException;
import be.atbash.util.resource.ResourceUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.spi.AnnotatedType;
import jakarta.enterprise.inject.spi.Extension;
import jakarta.enterprise.inject.spi.ProcessAnnotatedType;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 *
 */

public class InterdynExtension implements Extension {

    private Logger logger = LoggerFactory.getLogger(InterdynExtension.class);

    private boolean initialized;
    private boolean enabled;

    private List<String> classPatterns;

    public void processAnnotatedType(@Observes ProcessAnnotatedType pat) {
        checkConfig();
        if (!enabled) {
            return;
        }
        AnnotatedType at = pat.getAnnotatedType();
        Class<?> javaClass = at.getJavaClass();
        String beanClassName = javaClass.getName();

        if (javaClass.getAnnotation(ApplicationScoped.class) != null) {
            WrappedAnnotatedType wrappedAnnotatedType = null;
            for (String classPattern : classPatterns) {

                if (beanClassName.matches(classPattern)) {
                    if (wrappedAnnotatedType == null) {
                        wrappedAnnotatedType = new WrappedAnnotatedType(at);
                    }

                    Annotation interceptorAnnotation = () -> OctopusInterceptorBinding.class;
                    wrappedAnnotatedType.getAnnotations().add(interceptorAnnotation);

                    logger.info(String.format("Adding Dynamic Interceptor %s to class %s", OctopusInterceptorBinding.class, beanClassName));
                }
            }

            if (wrappedAnnotatedType != null) {
                pat.setAnnotatedType(wrappedAnnotatedType);
            }

        }
    }

    private void checkConfig() {
        if (initialized) {
            return;
        }
        enabled = OctopusCoreConfiguration.getInstance().getCDIInterceptorActive();
        if (enabled) {

            String configFile = OctopusCoreConfiguration.getInstance().getCDIInterceptorConfigFile();

            classPatterns = new ArrayList<>();
            try {
                InputStream inputStream = ResourceUtil.getInstance().getStream(configFile);
                if (inputStream != null) {

                    Scanner scanner = new Scanner(inputStream);
                    while (scanner.hasNextLine()) {
                        String configLine = scanner.nextLine();
                        classPatterns.add(configLine);
                    }
                    inputStream.close();
                } else {
                    logger.warn("Unable to read the contents from {}", configFile);
                }
            } catch (IOException e) {
                throw new AtbashUnexpectedException(e.getMessage());
            }
        }

        initialized = true;
    }

    public boolean isOctopusInternalClass(Class<?> javaClass) {
        boolean result = false;
        if (javaClass.getName().matches("be.atbash.ee.security.octopus.*")) {
            result = true;
        }

        if (!result) {
            if (AuthenticationInfoProvider.class.isAssignableFrom(javaClass)) {
                result = true;
            }
            if (AuthorizationInfoProvider.class.isAssignableFrom(javaClass)) {
                result = true;
            }
        }
        return result;
    }
}
