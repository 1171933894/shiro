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
package org.apache.shiro.session.mgt;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;

/**
 * A SessionManager manages the creation, maintenance, and clean-up of all application
 * {@link org.apache.shiro.session.Session Session}s.
 *
 * @since 0.1
 */

/**
 * SessionManager用于管理Shiro中的Session信息。Session也就是我们通常说的会话，会话是用户在使用应用程序一段时间内携带的数据。传统的会话一般是基于Web容器(如:Tomcat、EJB环境等)。Shiro提供的Session可以在任何环境中使用，不再依赖于其他容器
 */
public interface SessionManager {

    /**
     * Starts a new session based on the specified contextual initialization data, which can be used by the underlying
     * implementation to determine how exactly to create the internal Session instance.
     * <p/>
     * This method is mainly used in framework development, as the implementation will often relay the argument
     * to an underlying {@link SessionFactory} which could use the context to construct the internal Session
     * instance in a specific manner.  This allows pluggable {@link org.apache.shiro.session.Session Session} creation
     * logic by simply injecting a {@code SessionFactory} into the {@code SessionManager} instance.
     *
     * @param context the contextual initialization data that can be used by the implementation or underlying
     *                {@link SessionFactory} when instantiating the internal {@code Session} instance.
     * @return the newly created session.
     * @see SessionFactory#createSession(SessionContext)
     * @since 1.0
     */
    /**
     * 开始一个新的Session，context提供一些初始化的数据
     */
    Session start(SessionContext context);

    /**
     * Retrieves the session corresponding to the specified contextual data (such as a session ID if applicable), or
     * {@code null} if no Session could be found.  If a session is found but invalid (stopped or expired), a
     * {@link SessionException} will be thrown.
     *
     * @param key the Session key to use to look-up the Session
     * @return the {@code Session} instance corresponding to the given lookup key or {@code null} if no session
     *         could be acquired.
     * @throws SessionException if a session was found but it was invalid (stopped/expired).
     * @since 1.0
     */
    /**
     * 通过SessionKey查找Session
     * 如果存在则被找到，如果不存在则返回null；如果找到的Session无效(被停止或过期)则会抛异常
     */
    Session getSession(SessionKey key) throws SessionException;
}
