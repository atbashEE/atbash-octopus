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
package be.atbash.ee.security.octopus.subject;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.util.CDIUtils;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;

/**
 *
 */
@ApplicationScoped
public class PrincipalManager {

    private List<PrincipalConverter> converters;

    @PostConstruct
    public void init() {
        converters = CDIUtils.retrieveInstances(PrincipalConverter.class);
    }

    public <T extends ValidatedAuthenticationToken> T convert(Class<T> targetPrincipalClass) {

        Subject subject = SecurityUtils.getSubject();
        T result = subject.getPrincipals().oneByType(targetPrincipalClass);

        if (result == null) {
            Iterator<PrincipalConverter> iterator = converters.iterator();
            while (result == null && iterator.hasNext()) {

                PrincipalConverter converter = iterator.next();
                if (converter.supportFor(targetPrincipalClass)) {
                    result = (T) converter.convert(subject);
                }
            }
        }
        return result;
    }

    // Java SE support
    private static PrincipalManager INSTANCE;

    private static final Object LOCK = new Object();

    private void loadConverters() {
        converters = new ArrayList<>();

        for (PrincipalConverter principalConverter : ServiceLoader.load(PrincipalConverter.class)) {
            converters.add(principalConverter);
        }
    }

    public static PrincipalManager getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new PrincipalManager();
                    INSTANCE.loadConverters();
                }
            }
        }
        return INSTANCE;
    }

}
