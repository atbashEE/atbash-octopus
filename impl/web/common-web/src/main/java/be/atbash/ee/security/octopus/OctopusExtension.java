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
package be.atbash.ee.security.octopus;

import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.role.ApplicationRole;
import be.atbash.ee.security.octopus.authz.permission.role.NamedRole;
import be.atbash.ee.security.octopus.authz.permission.role.voter.GenericRoleVoter;
import be.atbash.ee.security.octopus.authz.permission.typesafe.PermissionLookup;
import be.atbash.ee.security.octopus.authz.permission.typesafe.RoleLookup;
import be.atbash.ee.security.octopus.authz.permission.voter.GenericPermissionVoter;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.config.names.VoterNameFactory;
import be.atbash.util.CDIUtils;
import org.apache.deltaspike.core.api.literal.NamedLiteral;
import org.apache.deltaspike.core.util.bean.BeanBuilder;
import org.apache.deltaspike.core.util.metadata.builder.DelegatingContextualLifecycle;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.*;

/**
 *
 */

public class OctopusExtension implements Extension {

    private Class<OctopusCoreConfiguration> configClass = OctopusCoreConfiguration.class;
    private Class<VoterNameFactory> voterNameFactoryClass = VoterNameFactory.class;

    protected OctopusCoreConfiguration config;
    protected VoterNameFactory nameFactory;

    protected void createPermissionVoters(AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {

        Class<? extends NamedPermission> namedPermissionClass = config.getNamedPermissionClass();

        if (namedPermissionClass != null) {

            Object[] constants = namedPermissionClass.getEnumConstants();

            AnnotatedType<GenericPermissionVoter> permissionVoterAnnotatedType = beanManager
                    .createAnnotatedType(GenericPermissionVoter.class);
            InjectionTarget<GenericPermissionVoter> voterInjectionTarget = beanManager
                    .createInjectionTarget(permissionVoterAnnotatedType);

            NamedPermission namedPermission;
            String beanName;

            for (Object permission : constants) {
                namedPermission = (NamedPermission) permission;
                beanName = nameFactory.generateBeanNameForExtension(namedPermission.name(), config.getPermissionVoterSuffix());

                Bean<GenericPermissionVoter> bean = new BeanBuilder<GenericPermissionVoter>(beanManager)
                        .passivationCapable(false).beanClass(GenericPermissionVoter.class)
                        .injectionPoints(voterInjectionTarget.getInjectionPoints()).name(beanName)
                        .scope(ApplicationScoped.class).qualifiers(new NamedLiteral(beanName))
                        .passivationCapable(true).id(beanName)
                        .beanLifecycle(new PermissionLifecycleCallback(voterInjectionTarget, namedPermission)).create();
                afterBeanDiscovery.addBean(bean);
            }
        }
    }

    protected void createRoleVoters(AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {

        Class<? extends NamedRole> namedRoleClass = config.getNamedRoleClass();

        if (namedRoleClass != null) {

            Object[] constants = namedRoleClass.getEnumConstants();

            AnnotatedType<GenericRoleVoter> roleVoterAnnotatedType = beanManager
                    .createAnnotatedType(GenericRoleVoter.class);
            InjectionTarget<GenericRoleVoter> voterInjectionTarget = beanManager
                    .createInjectionTarget(roleVoterAnnotatedType);

            NamedRole namedRole;
            String beanName;

            for (Object permission : constants) {
                namedRole = (NamedRole) permission;
                beanName = nameFactory.generateBeanNameForExtension(namedRole.name(), config.getRoleVoterSuffix());

                Bean<GenericRoleVoter> bean = new BeanBuilder<GenericRoleVoter>(beanManager)
                        .passivationCapable(false).beanClass(GenericRoleVoter.class)
                        .injectionPoints(voterInjectionTarget.getInjectionPoints()).name(beanName)
                        .scope(ApplicationScoped.class).qualifiers(new NamedLiteral(beanName))
                        .passivationCapable(true).id(beanName)
                        .beanLifecycle(new RoleLifecycleCallback(voterInjectionTarget, namedRole)).create();
                afterBeanDiscovery.addBean(bean);
            }
        }
    }

    private static class PermissionLifecycleCallback extends DelegatingContextualLifecycle<GenericPermissionVoter> {

        private NamedPermission namedPermission;

        public PermissionLifecycleCallback(InjectionTarget<GenericPermissionVoter> injectionTarget, NamedPermission
                someNamedPermission) {
            super(injectionTarget);
            namedPermission = someNamedPermission;
        }

        @Override
        public GenericPermissionVoter create(Bean<GenericPermissionVoter> bean,
                                             CreationalContext<GenericPermissionVoter> creationalContext) {
            GenericPermissionVoter result = super.create(bean, creationalContext);

            // We can't move this to the Extension itself.
            // The producer of this PermissionLookup goes to the database and this isn't possible until we are completely ready.

            PermissionLookup<? extends NamedPermission> permissionLookup = CDIUtils.retrieveOptionalInstance(PermissionLookup.class);
            if (permissionLookup == null) {
                throw new ConfigurationException("When using the named permissions, please configure them with the PermissionLookup.  See manual ??? TODO");
            }
            result.setNamedPermission(permissionLookup.getPermission(namedPermission.name()));
            return result;
        }

    }

    private static class RoleLifecycleCallback extends DelegatingContextualLifecycle<GenericRoleVoter> {

        private NamedRole namedRole;

        public RoleLifecycleCallback(InjectionTarget<GenericRoleVoter> injectionTarget, NamedRole
                someNamedRole) {
            super(injectionTarget);
            namedRole = someNamedRole;
        }

        @Override
        public GenericRoleVoter create(Bean<GenericRoleVoter> bean,
                                       CreationalContext<GenericRoleVoter> creationalContext) {
            GenericRoleVoter result = super.create(bean, creationalContext);

            // We can't move this to the Extension itself.
            // The producer of this RoleLookup goes to the database and this isn't possible until we are completely ready.
            RoleLookup<? extends NamedRole> roleLookup = CDIUtils.retrieveOptionalInstance(RoleLookup.class);
            if (roleLookup == null) {
                // TODO Should we cache these instances somewhere? (memory improvement)
                result.setNamedRole(new ApplicationRole(namedRole.name()));
            } else {

                result.setNamedRole(roleLookup.getRole(namedRole.name()));
            }
            return result;
        }

    }

    <T> void collectImplementations(@Observes ProcessAnnotatedType<T> pat, BeanManager beanManager) {
        AnnotatedType<T> annotatedType = pat.getAnnotatedType();
        if (OctopusCoreConfiguration.class.equals(annotatedType.getJavaClass().getSuperclass())) {
            configClass = (Class<OctopusCoreConfiguration>) annotatedType.getJavaClass();
        }

        if (VoterNameFactory.class.equals(annotatedType.getJavaClass().getSuperclass())) {
            voterNameFactoryClass = (Class<VoterNameFactory>) annotatedType.getJavaClass();
        }

    }

    void configModule(@Observes AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {
        config = getUnmanagedInstance(beanManager, configClass);

        nameFactory = getUnmanagedInstance(beanManager, voterNameFactoryClass);

        createPermissionVoters(afterBeanDiscovery, beanManager);
        createRoleVoters(afterBeanDiscovery, beanManager);

    }

    private <T> T getUnmanagedInstance(BeanManager beanManager, Class<T> beanClass) {
        Unmanaged<T> unmanagedConfig = new Unmanaged<T>(beanManager, beanClass);
        Unmanaged.UnmanagedInstance<? extends T> configInstance = unmanagedConfig.newInstance();
        return configInstance.produce().inject().postConstruct().get();
    }

}
