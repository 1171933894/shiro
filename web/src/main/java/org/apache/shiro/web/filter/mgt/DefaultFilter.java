/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.web.filter.mgt;

import org.apache.shiro.util.ClassUtils;
import org.apache.shiro.web.filter.InvalidRequestFilter;
import org.apache.shiro.web.filter.authc.*;
import org.apache.shiro.web.filter.authz.*;
import org.apache.shiro.web.filter.session.NoSessionCreationFilter;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Enum representing all of the default Shiro Filter instances available to web applications.  Each filter instance is
 * typically accessible in configuration the {@link #name() name} of the enum constant.
 *
 * @since 1.0
 */
public enum DefaultFilter {

    // 通用过滤器，任何请求允许访问
    anon(AnonymousFilter.class),
    // 表单认证过滤器
    authc(FormAuthenticationFilter.class),
    // 基于Http请求的认证过滤器
    authcBasic(BasicHttpAuthenticationFilter.class),
    authcBearer(BearerHttpAuthenticationFilter.class),
    // 登出过滤器
    logout(LogoutFilter.class),
    // 不创建Session过滤器
    noSessionCreation(NoSessionCreationFilter.class),
    // 权限认证过滤器
    perms(PermissionsAuthorizationFilter.class),
    // 端口过滤器
    port(PortFilter.class),
    // 请求处理为权限的一种过滤器
    rest(HttpMethodPermissionFilter.class),
    // 角色过滤器
    roles(RolesAuthorizationFilter.class),
    // SSL过滤器
    ssl(SslFilter.class),
    // 用户过滤器，检测用户是否登录
    user(UserFilter.class),
    invalidRequest(InvalidRequestFilter.class);

    private final Class<? extends Filter> filterClass;

    private DefaultFilter(Class<? extends Filter> filterClass) {
        this.filterClass = filterClass;
    }

    public Filter newInstance() {
        return (Filter) ClassUtils.newInstance(this.filterClass);
    }

    public Class<? extends Filter> getFilterClass() {
        return this.filterClass;
    }

    public static Map<String, Filter> createInstanceMap(FilterConfig config) {
        Map<String, Filter> filters = new LinkedHashMap<String, Filter>(values().length);
        for (DefaultFilter defaultFilter : values()) {
            Filter filter = defaultFilter.newInstance();
            if (config != null) {
                try {
                    filter.init(config);
                } catch (ServletException e) {
                    String msg = "Unable to correctly init default filter instance of type " +
                            filter.getClass().getName();
                    throw new IllegalStateException(msg, e);
                }
            }
            filters.put(defaultFilter.name(), filter);
        }
        return filters;
    }
}
