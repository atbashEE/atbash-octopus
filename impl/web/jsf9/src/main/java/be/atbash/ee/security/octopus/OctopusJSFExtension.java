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
package be.atbash.ee.security.octopus;

import be.atbash.ee.security.octopus.view.model.LoginBean;
import be.atbash.util.StringUtils;
import org.apache.deltaspike.core.util.bean.BeanBuilder;
import org.apache.deltaspike.core.util.metadata.builder.DelegatingContextualLifecycle;
import org.eclipse.microprofile.config.ConfigProvider;

import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.spi.*;
import java.util.NoSuchElementException;
import java.util.Set;

public class OctopusJSFExtension implements Extension {

    void configModule(@Observes AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {
        String aliasNameLoginBean = getAliasNameLoginBean();

        if (StringUtils.hasText(aliasNameLoginBean)) {
            setAlternativeNameForLoginBean(afterBeanDiscovery, beanManager, aliasNameLoginBean);
        }
    }

    private String getAliasNameLoginBean() {
        // We are bypassing OctopusJSFConfiguration but there are issues getting the value through Unmanaged Instance.
        // If needed, We could try to fallback to the Java EE 6 way by getting just a contextual reference.
        // But the getOptionalValue can't be used since we are still using atbash-config for Java 7 and on a Java 8
        // version with a real MP config implementation, the getOptionalValue returns Optional<String>
        // This was solved in the AbstractConfiguration but we are not using this.

        // So this is now very hacky
        try {
            return ConfigProvider.getConfig().getValue("aliasNameLoginBean", String.class);
        } catch (NoSuchElementException e) {
            return null;
        }
    }


    private void setAlternativeNameForLoginBean(AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager, String aliasNameLoginBean) {
        Set<Bean<?>> beans = beanManager.getBeans("loginBean");

        AnnotatedType<LoginBean> loginBeanAnnotatedType = beanManager
                .createAnnotatedType(LoginBean.class);
        InjectionTarget<LoginBean> loginInjectionTarget = beanManager
                .createInjectionTarget(loginBeanAnnotatedType);

        for (Bean<?> bean : beans) {

            Bean<LoginBean> newBean = new BeanBuilder<LoginBean>(beanManager)
                    .passivationCapable(false).beanClass(LoginBean.class)
                    .injectionPoints(bean.getInjectionPoints()).name(aliasNameLoginBean)
                    .scope(bean.getScope()).qualifiers(bean.getQualifiers())
                    .types(bean.getTypes()).alternative(bean.isAlternative()).nullable(bean.isNullable())
                    .stereotypes(bean.getStereotypes())
                    .beanLifecycle(new DelegatingContextualLifecycle(loginInjectionTarget)).create();
            afterBeanDiscovery.addBean(newBean);

        }
    }

}
