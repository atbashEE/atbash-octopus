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
package be.atbash.ee.security.octopus.filter.authz;

import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.PermissionResolver;
import be.atbash.ee.security.octopus.authz.permission.WildcardPermission;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.subject.WebSubject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import java.util.List;

import static be.atbash.ee.security.octopus.authz.permission.testclasses.TestPermission.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class NamedPermissionOneFilterTest {

    @Mock
    private WebSubject subjectMock;

    @Mock
    private PermissionResolver permissionResolverMock;

    @InjectMocks
    private NamedPermissionOneFilter filter;

    @Captor
    private ArgumentCaptor<Permission> permissionArgumentCaptor;

    @Before
    public void setUp() {
        ThreadContext.bind(subjectMock);

        when(permissionResolverMock.resolvePermission("PERMISSION1")).thenReturn(new NamedDomainPermission("PERMISSION1", "permission:1:*"));
        when(permissionResolverMock.resolvePermission("PERMISSION2")).thenReturn(new NamedDomainPermission("PERMISSION2", "permission:2:*"));
        when(permissionResolverMock.resolvePermission("PERMISSION3")).thenReturn(new NamedDomainPermission("PERMISSION3", "permission:3:*"));
        when(permissionResolverMock.resolvePermission("permission1")).thenReturn(new NamedDomainPermission("PERMISSION1", "spermission:1:*"));
        when(permissionResolverMock.resolvePermission("permission2")).thenReturn(new NamedDomainPermission("PERMISSION2", "spermission:2:*"));
        when(permissionResolverMock.resolvePermission("permission3")).thenReturn(new NamedDomainPermission("PERMISSION3", "spermission:3:*"));
        when(permissionResolverMock.resolvePermission("junit")).thenReturn(new WildcardPermission("junit:*:*"));
        when(permissionResolverMock.resolvePermission("junit:permission:1")).thenReturn(new WildcardPermission("junit:permission:1"));

    }

    @Test
    public void isAccessAllowed_NamedTypeSafe_Allowed() throws Exception {

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{PERMISSION1.name()});
        assertThat(accessAllowed).isTrue();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo("permission:1:*");
    }

    @Test
    public void isAccessAllowed_NamedTypeSafe_NotAllowed() throws Exception {

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(false);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{PERMISSION3.name()});

        assertThat(accessAllowed).isFalse();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo("permission:3:*");

    }

    @Test
    public void isAccessAllowed_NamedTypeSafe_Multiple_Found() throws Exception {

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{PERMISSION1.name(), PERMISSION2.name()});
        assertThat(accessAllowed).isTrue();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        Permission permission = allValues.get(0);
        assertThat(permission.toString()).isEqualTo("permission:1:*");

        permission = allValues.get(1);
        assertThat(permission.toString()).isEqualTo("permission:2:*");
    }

    @Test
    public void isAccessAllowed_NamedTypeSafe_Multiple_OneIsEnoughForTheFilter() throws Exception {

        when(subjectMock.isPermitted(any(Permission.class))).thenAnswer(new Answer<Object>() {
            @Override
            public Boolean answer(InvocationOnMock invocation) throws Throwable {
                Permission permission = (Permission) invocation.getArguments()[0];
                return "permission:1:*".equals(permission.toString());
            }
        });

        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{PERMISSION1.name(), PERMISSION2.name()});
        assertThat(accessAllowed).isTrue();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        NamedDomainPermission permission = (NamedDomainPermission) allValues.get(0);
        assertThat(permission.toString()).isEqualTo("permission:1:*");

        permission = (NamedDomainPermission) allValues.get(1);
        assertThat(permission.toString()).isEqualTo("permission:2:*");
    }

    @Test
    public void isAccessAllowed_NamedStrings_Allowed() throws Exception {

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{"permission1"});
        assertThat(accessAllowed).isTrue();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo("spermission:1:*");
    }

    @Test
    public void isAccessAllowed_NamedString_NotAllowed() throws Exception {

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(false);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{"permission3"});

        assertThat(accessAllowed).isFalse();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo("spermission:3:*");

    }

    @Test
    public void isAccessAllowed_NamedString_Multiple_Found() throws Exception {

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{"permission1", "permission2"});
        assertThat(accessAllowed).isTrue();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        Permission permission = allValues.get(0);
        assertThat(permission.toString()).isEqualTo("spermission:1:*");

        permission = allValues.get(1);
        assertThat(permission.toString()).isEqualTo("spermission:2:*");
    }

    @Test
    public void isAccessAllowed_NamedString_Multiple_OneIsEnoughForFilter() throws Exception {

        when(subjectMock.isPermitted(any(Permission.class))).thenAnswer(new Answer<Object>() {
            @Override
            public Boolean answer(InvocationOnMock invocation) throws Throwable {
                Permission permission = (Permission) invocation.getArguments()[0];
                return "spermission:1:*".equals(permission.toString());
            }
        });

        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{"permission1", "permission2"});
        assertThat(accessAllowed).isTrue();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(NamedDomainPermission.class);

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        NamedDomainPermission permission = (NamedDomainPermission) allValues.get(0);
        assertThat(permission.toString()).isEqualTo("spermission:1:*");

        permission = (NamedDomainPermission) allValues.get(1);
        assertThat(permission.toString()).isEqualTo("spermission:2:*");
    }

    @Test
    public void isAccessAllowed_Wildcard_Allowed() throws Exception {

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{"junit:permission:1"});
        assertThat(accessAllowed).isTrue();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(WildcardPermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo("junit:permission:1");
    }

    @Test
    public void isAccessAllowed_Simple_Allowed() throws Exception {

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(false);
        boolean accessAllowed = filter.isAccessAllowed(null, null, new String[]{"junit"});
        assertThat(accessAllowed).isFalse();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(WildcardPermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo("junit:*:*");
    }

}