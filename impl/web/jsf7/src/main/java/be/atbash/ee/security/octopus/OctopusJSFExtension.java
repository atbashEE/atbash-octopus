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
package be.atbash.ee.security.octopus;

import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.view.model.LoginBean;
import org.apache.deltaspike.core.util.bean.BeanBuilder;
import org.apache.deltaspike.core.util.metadata.builder.DelegatingContextualLifecycle;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.*;
import java.util.Set;

public class OctopusJSFExtension implements Extension {

    private OctopusJSFConfiguration config;

    private Class<OctopusJSFConfiguration> configClass = OctopusJSFConfiguration.class;

    void configModule(@Observes AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {
        config = getUnmanagedInstance(beanManager, configClass);

        if (config.getAliasNameLoginbean().length() != 0) {
            setAlternativeNameForLoginBean(afterBeanDiscovery, beanManager);
        }
    }


    private void setAlternativeNameForLoginBean(AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {
        Set<Bean<?>> beans = beanManager.getBeans("loginBean");

        AnnotatedType<LoginBean> loginBeanAnnotatedType = beanManager
                .createAnnotatedType(LoginBean.class);
        InjectionTarget<LoginBean> loginInjectionTarget = beanManager
                .createInjectionTarget(loginBeanAnnotatedType);

        for (Bean<?> bean : beans) {

            Bean<LoginBean> newBean = new BeanBuilder<LoginBean>(beanManager)
                    .passivationCapable(false).beanClass(LoginBean.class)
                    .injectionPoints(bean.getInjectionPoints()).name(config.getAliasNameLoginbean())
                    .scope(bean.getScope()).qualifiers(bean.getQualifiers())
                    .types(bean.getTypes()).alternative(bean.isAlternative()).nullable(bean.isNullable())
                    .stereotypes(bean.getStereotypes())
                    .beanLifecycle(new DelegatingContextualLifecycle(loginInjectionTarget)).create();
            afterBeanDiscovery.addBean(newBean);

        }
    }

    private <T> T getUnmanagedInstance(BeanManager beanManager, Class<T> beanClass) {
        Unmanaged<T> unmanagedConfig = new Unmanaged<T>(beanManager, beanClass);
        Unmanaged.UnmanagedInstance<? extends T> configInstance = unmanagedConfig.newInstance();
        return configInstance.produce().inject().postConstruct().get();
    }

}
