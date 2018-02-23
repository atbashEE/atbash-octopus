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
package be.atbash.ee.security.octopus.view.component.secured;

import be.atbash.ee.security.octopus.authz.Combined;
import be.atbash.ee.security.octopus.config.names.VoterNameFactory;
import be.atbash.ee.security.octopus.view.component.OctopusComponentUsageException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.faces.component.UIComponentBase;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 */
@RunWith(MockitoJUnitRunner.class)
public class OctopusHandlerHelperTest {

    private UIComponentBase component = new UIComponentBase() {
        @Override
        public String getFamily() {
            return null;
        }
    };

    @Mock
    private VoterNameFactory voterNameFactoryMock;

    @InjectMocks
    private OctopusHandlerHelper handlerHelper;

    @Before
    public void setup() throws IllegalAccessException {
        when(voterNameFactoryMock.generatePermissionBeanName("myPermission")).thenReturn("myPermissionVoter");
        when(voterNameFactoryMock.generateRoleBeanName("theRole")).thenReturn("theRoleVoter");

    }

    @Test
    public void gatherSecurityInfo_voter() {
        component.getAttributes().put("voter", "complexVoter");

        SecuredComponentData componentData = handlerHelper.gatherSecurityInfo(component, null);
        assertThat(componentData).isNotNull();
        assertThat(componentData.getVoters()).contains("complexVoter");
    }

    @Test
    public void gatherSecurityInfo_permission() {
        component.getAttributes().put("permission", "myPermission");

        SecuredComponentData componentData = handlerHelper.gatherSecurityInfo(component, null);
        assertThat(componentData).isNotNull();
        assertThat(componentData.getVoters()).contains("myPermissionVoter");
    }

    @Test
    public void gatherSecurityInfo_role() {
        component.getAttributes().put("role", "theRole");

        SecuredComponentData componentData = handlerHelper.gatherSecurityInfo(component, null);
        assertThat(componentData).isNotNull();
        assertThat(componentData.getVoters()).contains("theRoleVoter");
    }

    @Test
    public void gatherSecurityInfo_voter_permission() {
        component.getAttributes().put("voter", "complexVoter");
        component.getAttributes().put("permission", "myPermission");

        SecuredComponentData componentData = handlerHelper.gatherSecurityInfo(component, null);
        assertThat(componentData).isNotNull();
        assertThat(componentData.getVoters()).contains("complexVoter", "myPermissionVoter");
    }

    @Test
    public void gatherSecurityInfo_voter_role() {
        component.getAttributes().put("voter", "complexVoter");
        component.getAttributes().put("role", "theRole");

        SecuredComponentData componentData = handlerHelper.gatherSecurityInfo(component, null);
        assertThat(componentData).isNotNull();
        assertThat(componentData.getVoters()).contains("complexVoter", "theRoleVoter");
    }

    @Test
    public void gatherSecurityInfo_voter_permission_role() {
        component.getAttributes().put("voter", "complexVoter");
        component.getAttributes().put("permission", "myPermission");
        component.getAttributes().put("role", "theRole");

        SecuredComponentData componentData = handlerHelper.gatherSecurityInfo(component, null);
        assertThat(componentData).isNotNull();
        assertThat(componentData.getVoters()).contains("complexVoter", "myPermissionVoter", "theRoleVoter");
    }

    @Test(expected = OctopusComponentUsageException.class)
    public void gatherSecurityInfo_no_Voter_permission_role() {

        handlerHelper.gatherSecurityInfo(component, null);

    }

    @Test
    public void gatherSecurityInfo_not_combined_defaults() {
        component.getAttributes().put("voter", "complexVoter");

        SecuredComponentData componentData = handlerHelper.gatherSecurityInfo(component, null);
        assertThat(componentData).isNotNull();
        assertThat(componentData.isNot()).isFalse();
        assertThat(componentData.getCombined()).isEqualTo(Combined.OR);
    }

    @Test
    public void gatherSecurityInfo_not_combined() {
        component.getAttributes().put("voter", "complexVoter");
        component.getAttributes().put("not", "true");
        component.getAttributes().put("combined", "TrUe");

        SecuredComponentData componentData = handlerHelper.gatherSecurityInfo(component, null);
        assertThat(componentData).isNotNull();
        assertThat(componentData.isNot()).isTrue();
        assertThat(componentData.getCombined()).isEqualTo(Combined.AND);
    }

}