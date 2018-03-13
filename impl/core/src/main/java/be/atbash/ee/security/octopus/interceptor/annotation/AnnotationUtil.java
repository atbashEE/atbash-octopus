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
package be.atbash.ee.security.octopus.interceptor.annotation;

import be.atbash.ee.security.octopus.authz.Combined;
import be.atbash.ee.security.octopus.authz.annotation.*;
import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.role.NamedRole;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.systemaccount.SystemAccount;
import be.atbash.util.CDIUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import be.atbash.util.reflection.ClassUtils;

import javax.annotation.security.PermitAll;
import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

// TODO JavaDoc
public final class AnnotationUtil {

    private AnnotationUtil() {
    }

    public static <T extends NamedPermission> T[] getPermissionValues(Annotation someCustomNamedCheck) {
        T[] result = null;
        for (Method method : someCustomNamedCheck.getClass().getDeclaredMethods()) {
            if ("value".equals(method.getName())) {
                try {
                    result = (T[]) method.invoke(someCustomNamedCheck, null);
                } catch (IllegalAccessException | InvocationTargetException e) {
                    throw new AtbashUnexpectedException(e);
                }
            }
        }

        return result;
    }

    public static String[] getStringValues(Annotation someCustomNamedCheck) {
        String[] result = null;
        for (Method method : someCustomNamedCheck.getClass().getDeclaredMethods()) {
            if ("value".equals(method.getName())) {
                try {
                    Object value = method.invoke(someCustomNamedCheck, null);
                    if (value.getClass().isArray()) {
                        result = (String[]) value;
                    } else {
                        result = new String[]{value.toString()};
                    }

                } catch (IllegalAccessException | InvocationTargetException e) {
                    throw new AtbashUnexpectedException(e);
                }
            }
        }

        return result;
    }

    // FIXME Required for the advanced custom annotation feature.
    public static boolean hasAdvancedFlag(Annotation someAnnotation) {
        boolean result = false;

        for (Method method : someAnnotation.getClass().getDeclaredMethods()) {
            if ("advanced".equals(method.getName())) {
                try {
                    Object value = method.invoke(someAnnotation, null);

                    result = Boolean.valueOf(value.toString());
                } catch (IllegalAccessException | InvocationTargetException e) {
                    throw new AtbashUnexpectedException(e);
                }
            }
        }

        return result;
    }

    public static <T extends NamedRole> T[] getRoleValues(Annotation someCustomRoleCheck) {
        T[] result = null;
        for (Method method : someCustomRoleCheck.getClass().getDeclaredMethods()) {
            if ("value".equals(method.getName())) {
                try {
                    result = (T[]) method.invoke(someCustomRoleCheck, null);

                } catch (IllegalAccessException | InvocationTargetException e) {
                    throw new AtbashUnexpectedException(e);
                }
            }
        }

        return result;
    }

    public static Combined getPermissionCombination(Annotation customAnnotation) {
        String value = null;
        for (Method method : customAnnotation.getClass().getDeclaredMethods()) {
            // The initial element(method) which was used
            if ("combine".equals(method.getName())) {
                try {
                    value = method.invoke(customAnnotation, null).toString();

                } catch (IllegalAccessException | InvocationTargetException e) {
                    throw new AtbashUnexpectedException(e);
                }
            }
            // But the securedComponent used combined attribute. So that is why requiresPermissions and RequiresRoles also uses combined.
            if ("combined".equals(method.getName())) {
                try {
                    value = method.invoke(customAnnotation, null).toString();

                } catch (IllegalAccessException | InvocationTargetException e) {
                    throw new AtbashUnexpectedException(e);
                }
            }
        }
        return Combined.findFor(value);
    }

    // Retrieve the supported annotation enforcing authorization for the method
    public static AnnotationInfo getAllAnnotations(OctopusCoreConfiguration config, Class<?> classType, Method method) {

        AnnotationInfo result = new AnnotationInfo();

        result.addMethodAnnotation(method.getAnnotation(PermitAll.class));
        result.addMethodAnnotation(method.getAnnotation(RequiresAuthentication.class));
        result.addMethodAnnotation(method.getAnnotation(RequiresGuest.class));
        result.addMethodAnnotation(method.getAnnotation(RequiresUser.class));
        result.addMethodAnnotation(method.getAnnotation(RequiresRoles.class));
        result.addMethodAnnotation(method.getAnnotation(RequiresPermissions.class));
        result.addMethodAnnotation(method.getAnnotation(CustomVoterCheck.class));
        result.addMethodAnnotation(method.getAnnotation(SystemAccount.class));
        result.addMethodAnnotation(method.getAnnotation(OnlyDuringAuthorization.class));
        result.addMethodAnnotation(method.getAnnotation(OnlyDuringAuthentication.class));
        result.addMethodAnnotation(method.getAnnotation(OnlyDuringAuthenticationEvent.class));
        if (config.getNamedPermissionCheckClass() != null) {
            result.addMethodAnnotation(method.getAnnotation(config.getNamedPermissionCheckClass()));
        }
        if (config.getNamedRoleCheckClass() != null) {
            result.addMethodAnnotation(method.getAnnotation(config.getNamedRoleCheckClass()));
        }
        if (config.getCustomCheckClass() != null) {
            result.addMethodAnnotation(method.getAnnotation(config.getCustomCheckClass()));
        }

        List<AnnotationsToFind> annotationsToFindList = new ArrayList<>();
        if (ClassUtils.isAvailable("javax.enterprise.inject.UnsatisfiedResolutionException")) {
            annotationsToFindList = CDIUtils.retrieveInstances(AnnotationsToFind.class);
        }
        // Else, We don't have CDI so don't retrieve the AnnotationsToFind classes.
        // TODO is it OK that we don't use this in Java SE. Or should we use ServiceLoader?

        for (AnnotationsToFind annotationsToFind : annotationsToFindList) {
            for (Class<? extends Annotation> annotationClass : annotationsToFind.getList()) {
                result.addMethodAnnotation(method.getAnnotation(annotationClass));
            }
        }
        result.addClassAnnotation(getAnnotation(classType, PermitAll.class));
        result.addClassAnnotation(getAnnotation(classType, RequiresAuthentication.class));
        result.addClassAnnotation(getAnnotation(classType, RequiresGuest.class));
        result.addClassAnnotation(getAnnotation(classType, RequiresUser.class));
        result.addClassAnnotation(getAnnotation(classType, RequiresRoles.class));
        result.addClassAnnotation(getAnnotation(classType, RequiresPermissions.class));
        result.addClassAnnotation(getAnnotation(classType, CustomVoterCheck.class));
        result.addClassAnnotation(getAnnotation(classType, SystemAccount.class));
        if (config.getNamedPermissionCheckClass() != null) {
            result.addClassAnnotation(getAnnotation(classType, config.getNamedPermissionCheckClass()));
        }
        if (config.getNamedRoleCheckClass() != null) {
            result.addClassAnnotation(getAnnotation(classType, config.getNamedRoleCheckClass()));
        }
        if (config.getCustomCheckClass() != null) {
            result.addClassAnnotation(getAnnotation(classType, config.getCustomCheckClass()));
        }
        for (AnnotationsToFind annotationsToFind : annotationsToFindList) {
            for (Class<? extends Annotation> annotationClass : annotationsToFind.getList()) {
                result.addClassAnnotation(getAnnotation(classType, annotationClass));
            }
        }

        return result;
    }

    public static <A extends Annotation> A getAnnotation(Class<?> someClass, Class<A> someAnnotation) {
        A result = null;
        if (someClass.isAnnotationPresent(someAnnotation)) {
            result = someClass.getAnnotation(someAnnotation);
        } else {
            if (someClass != Object.class) {
                result = getAnnotation(someClass.getSuperclass(), someAnnotation);
            }
        }
        return result;
    }

    public static <A extends Annotation> boolean hasAnnotation(Set<?> annotations, Class<A> someAnnotation) {
        return getAnnotation(annotations, someAnnotation) != null;
    }

    private static <A extends Annotation> A getAnnotation(Set<?> annotations, Class<A> someAnnotation) {
        Object result = null;
        Iterator<?> iter = annotations.iterator();
        while (iter.hasNext() && result == null) {
            Object item = iter.next();
            if (someAnnotation.isAssignableFrom(item.getClass())) {
                result = item;
            }
        }
        return (A) result;
    }

}
