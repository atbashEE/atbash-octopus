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
package be.atbash.ee.security.octopus.config.names;

import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.authz.permission.typesafe.PermissionLookupFixture;
import be.atbash.ee.security.octopus.authz.permission.typesafe.RoleLookup;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 *
 */
@ExtendWith(MockitoExtension.class)
public class VoterNameFactoryTest {

    @Mock
    private OctopusCoreConfiguration octopusConfigMock;

    private VoterNameFactory factory;

    private BeanManagerFake beanManagerFake;

    @BeforeEach
    public void setup() {
        beanManagerFake = new BeanManagerFake();
        beanManagerFake.registerBean(octopusConfigMock, OctopusCoreConfiguration.class);

        factory = new VoterNameFactory();

        lenient().when(octopusConfigMock.getPermissionVoterSuffix()).thenReturn("PermissionVoter");
        lenient().when(octopusConfigMock.getRoleVoterSuffix()).thenReturn("RoleVoter");
        lenient().when(octopusConfigMock.getCustomCheckSuffix()).thenReturn("AccessDecissionVoter");

    }

    @AfterEach
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void generatePermissionBeanName_TyeSafeVersion() {
        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        // Finish preparation
        beanManagerFake.endRegistration();

        when(octopusConfigMock.getPermissionVoterSuffix()).thenReturn("PermissionVoter");

        String beanName = factory.generatePermissionBeanName("PERMISSION1");
        assertThat(beanName).isEqualTo("permission1PermissionVoter");

    }

    @Test
    public void generatePermissionBeanName_AlternativeName() {
        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        // Finish preparation
        beanManagerFake.endRegistration();

        when(octopusConfigMock.getPermissionVoterSuffix()).thenReturn("JUnit");

        String beanName = factory.generatePermissionBeanName("PERMISSION1");
        assertThat(beanName).isEqualTo("permission1JUnit");

    }

    @Test
    public void generateBeanNameForExtension() {

        // Finish preparation
        beanManagerFake.endRegistration();

        String beanName = factory.generateBeanNameForExtension("PERMISSION1", "SpecialName");
        assertThat(beanName).isEqualTo("permission1SpecialName");

    }

    @Test
    public void generatePermissionBeanName_TyeSafeVersion_Multiple() {
        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        // Finish preparation
        beanManagerFake.endRegistration();

        when(octopusConfigMock.getPermissionVoterSuffix()).thenReturn("PermissionVoter");

        String beanName = factory.generatePermissionBeanName("PERMISSION1, PERMISSION2");
        assertThat(beanName).isEqualTo("permission1PermissionVoter, permission2PermissionVoter");

    }

    @Test
    public void generatePermissionBeanName_StringVersion() {
        // Finish preparation
        beanManagerFake.endRegistration();

        // The : is in front; so that at other places we can detect it is a name
        String beanName = factory.generatePermissionBeanName("X");
        assertThat(beanName).isEqualTo(":X");

    }

    @Test
    public void generatePermissionBeanName_StringVersion_Multiple() {
        // Finish preparation
        beanManagerFake.endRegistration();

        // The : is in front; so that at other places we can detect it is a name
        String beanName = factory.generatePermissionBeanName("X, Y");
        assertThat(beanName).isEqualTo(":X, :Y");

    }

    @Test
    public void generatePermissionBeanName_WildCardVersion() {
        // Finish preparation
        beanManagerFake.endRegistration();

        String beanName = factory.generatePermissionBeanName("octopus:test:*");
        assertThat(beanName).isEqualTo("octopus:test:*");

    }

    @Test
    public void generatePermissionBeanName_WildCardVersion_Multiple() {
        // Finish preparation
        beanManagerFake.endRegistration();

        String beanName = factory.generatePermissionBeanName("octopus:test:*, octopus:test:second");
        assertThat(beanName).isEqualTo("octopus:test:*, octopus:test:second");

    }

    @Test
    public void generateRoleBeanName_StringName() {
        // Finish preparation
        beanManagerFake.endRegistration();

        String beanName = factory.generateRoleBeanName("myRole");
        assertThat(beanName).isEqualTo("::myRole");
    }

    @Test
    public void generateRoleBeanName_LookupVersion() {

        RoleLookup roleLookupMock = Mockito.mock(RoleLookup.class);
        beanManagerFake.registerBean(roleLookupMock, RoleLookup.class);

        // Finish preparation
        beanManagerFake.endRegistration();

        RolePermission namedRole = new RolePermission("JUnitRole");
        when(roleLookupMock.getRole("myRole")).thenReturn(namedRole);

        String beanName = factory.generateRoleBeanName("myRole");
        assertThat(beanName).isEqualTo("myroleRoleVoter");
    }

    @Test
    public void generateCustomCheckBeanName() {

        // Finish preparation
        beanManagerFake.endRegistration();

        String beanName = factory.generateCustomCheckBeanName("MyCheck");
        assertThat(beanName).isEqualTo("myCheckAccessDecissionVoter");
    }

}