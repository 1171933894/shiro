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
package org.apache.shiro.authc;

/**
 * An Authenticator is responsible for authenticating accounts in an application.  It
 * is one of the primary entry points into the Shiro API.
 * <p/>
 * Although not a requirement, there is usually a single 'master' Authenticator configured for
 * an application.  Enabling Pluggable Authentication Module (PAM) behavior
 * (Two Phase Commit, etc.) is usually achieved by the single {@code Authenticator} coordinating
 * and interacting with an application-configured set of {@link org.apache.shiro.realm.Realm Realm}s.
 * <p/>
 * Note that most Shiro users will not interact with an {@code Authenticator} instance directly.
 * Shiro's default architecture is based on an overall {@code SecurityManager} which typically
 * wraps an {@code Authenticator} instance.
 *
 * @see org.apache.shiro.mgt.SecurityManager
 * @see AbstractAuthenticator AbstractAuthenticator
 * @see org.apache.shiro.authc.pam.ModularRealmAuthenticator ModularRealmAuthenticator
 * @since 0.1
 */

/**
 * Authenticator就是认证器，在Shiro中负责认证用户提交的信息，在Shiro中我们用AuthenticationToken来表示提交的信息。Authenticator接口只提供了一个认证的方法
 *
 * Authenticator负责对AuthenticationToken进行认证，然后返回一个已经被认证过的信息AuthenticationInfo。Authenticator也提供了监听器AuthenticationListener，对认证状态进行监听。Authenticator真实的认证过程是由Realm来处理的，可以支持都多个Realm来认证，认证的过程中可以选择不同的认证策略。
 */
public interface Authenticator {

    /**
     * Authenticates a user based on the submitted {@code AuthenticationToken}.
     * <p/>
     * If the authentication is successful, an {@link AuthenticationInfo} instance is returned that represents the
     * user's account data relevant to Shiro.  This returned object is generally used in turn to construct a
     * {@code Subject} representing a more complete security-specific 'view' of an account that also allows access to
     * a {@code Session}.
     *
     * @param authenticationToken any representation of a user's principals and credentials submitted during an
     *                            authentication attempt.
     * @return the AuthenticationInfo representing the authenticating user's account data.
     * @throws AuthenticationException if there is any problem during the authentication process.
     *                                 See the specific exceptions listed below to as examples of what could happen
     *                                 in order to accurately handle these problems and to notify the user in an
     *                                 appropriate manner why the authentication attempt failed.  Realize an
     *                                 implementation of this interface may or may not throw those listed or may
     *                                 throw other AuthenticationExceptions, but the list shows the most common ones.
     * @see ExpiredCredentialsException
     * @see IncorrectCredentialsException
     * @see ExcessiveAttemptsException
     * @see LockedAccountException
     * @see ConcurrentAccessException
     * @see UnknownAccountException
     */
    /**
     * 认证用户提交的信息AuthenticationToken对象，AuthenticationToken包含了身份和凭证。
     * 如果认证成功则返回AuthenticationInfo对象，AuthenticationInfo对象代表了用户在Shiro中已经被认证过的账户数据。
     * 如果认证失败则抛出一下异常
     * @see ExpiredCredentialsException     凭证过期
     * @see IncorrectCredentialsException   凭证错误
     * @see ExcessiveAttemptsException      多次尝试失败
     * @see LockedAccountException          账户锁定
     * @see ConcurrentAccessException       并发访问异常(多点登录)
     * @see UnknownAccountException         账户未知
     */
    public AuthenticationInfo authenticate(AuthenticationToken authenticationToken)
            throws AuthenticationException;
}
