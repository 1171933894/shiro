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

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.LifecycleUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;


/**
 * Default business-tier implementation of the {@link ValidatingSessionManager} interface.
 *
 * @since 0.1
 */
public abstract class AbstractValidatingSessionManager extends AbstractNativeSessionManager
        implements ValidatingSessionManager, Destroyable {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(AbstractValidatingSessionManager.class);

    /**
     * The default interval at which sessions will be validated (1 hour);
     * This can be overridden by calling {@link #setSessionValidationInterval(long)}
     */
    public static final long DEFAULT_SESSION_VALIDATION_INTERVAL = MILLIS_PER_HOUR;

    // 标识是否需要校验Sesion
    protected boolean sessionValidationSchedulerEnabled;

    /**
     * Scheduler used to validate sessions on a regular basis.
     */
    // 从名称上看，我们就知道这个一个调度器。用来定时调度校验Session
    protected SessionValidationScheduler sessionValidationScheduler;

    // 调度器调度的时间间隔
    protected long sessionValidationInterval;

    public AbstractValidatingSessionManager() {
        this.sessionValidationSchedulerEnabled = true;
        this.sessionValidationInterval = DEFAULT_SESSION_VALIDATION_INTERVAL;
    }

    public boolean isSessionValidationSchedulerEnabled() {
        return sessionValidationSchedulerEnabled;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setSessionValidationSchedulerEnabled(boolean sessionValidationSchedulerEnabled) {
        this.sessionValidationSchedulerEnabled = sessionValidationSchedulerEnabled;
    }

    public void setSessionValidationScheduler(SessionValidationScheduler sessionValidationScheduler) {
        this.sessionValidationScheduler = sessionValidationScheduler;
    }

    public SessionValidationScheduler getSessionValidationScheduler() {
        return sessionValidationScheduler;
    }

    /**
     * 这个方法就是判断是否需要校验，如果需要校验就去开启调度作业
     **/
    private void enableSessionValidationIfNecessary() {
        SessionValidationScheduler scheduler = getSessionValidationScheduler();
        // 首先，判断是否需要校验Session，如果为false，则永远不会开启校验，根本就不判断scheduler的状态；
        // 其次，如果需要校验Session，会去判断scheduler== null或scheduler没有启动，在这两种情况下都会去开启调度任务
        // 也就是说，如果任务没有开启就去开启，如果已经开启了，就不会在处理。
        if (isSessionValidationSchedulerEnabled() && (scheduler == null || !scheduler.isEnabled())) {
            enableSessionValidation();
        }
    }

    /**
     * If using the underlying default <tt>SessionValidationScheduler</tt> (that is, the
     * {@link #setSessionValidationScheduler(SessionValidationScheduler) setSessionValidationScheduler} method is
     * never called) , this method allows one to specify how
     * frequently session should be validated (to check for orphans).  The default value is
     * {@link #DEFAULT_SESSION_VALIDATION_INTERVAL}.
     * <p/>
     * If you override the default scheduler, it is assumed that overriding instance 'knows' how often to
     * validate sessions, and this attribute will be ignored.
     * <p/>
     * Unless this method is called, the default value is {@link #DEFAULT_SESSION_VALIDATION_INTERVAL}.
     *
     * @param sessionValidationInterval the time in milliseconds between checking for valid sessions to reap orphans.
     */
    public void setSessionValidationInterval(long sessionValidationInterval) {
        this.sessionValidationInterval = sessionValidationInterval;
    }

    public long getSessionValidationInterval() {
        return sessionValidationInterval;
    }

    @Override
    protected final Session doGetSession(final SessionKey key) throws InvalidSessionException {
        enableSessionValidationIfNecessary();

        log.trace("Attempting to retrieve session with key {}", key);

        Session s = retrieveSession(key);
        if (s != null) {
            validate(s, key);
        }
        return s;
    }

    /**
     * Looks up a session from the underlying data store based on the specified session key.
     *
     * @param key the session key to use to look up the target session.
     * @return the session identified by {@code sessionId}.
     * @throws UnknownSessionException if there is no session identified by {@code sessionId}.
     */
    protected abstract Session retrieveSession(SessionKey key) throws UnknownSessionException;

    /**
     * 实现createSession方法
     */
    protected Session createSession(SessionContext context) throws AuthorizationException {
        // 这就是上面分析过的方法，判断是否需要校验和启动调度作业
        enableSessionValidationIfNecessary();
        // 继续提供抽象方法由子类实现怎么创建Session
        return doCreateSession(context);
    }

    /**
     * 实现doGetSession方法
     */
    protected abstract Session doCreateSession(SessionContext initData) throws AuthorizationException;

    protected void validate(Session session, SessionKey key) throws InvalidSessionException {
        try {
            doValidate(session);
        } catch (ExpiredSessionException ese) {
            onExpiration(session, ese, key);
            throw ese;
        } catch (InvalidSessionException ise) {
            onInvalidation(session, ise, key);
            throw ise;
        }
    }

    protected void onExpiration(Session s, ExpiredSessionException ese, SessionKey key) {
        log.trace("Session with id [{}] has expired.", s.getId());
        try {
            onExpiration(s);
            notifyExpiration(s);
        } finally {
            afterExpired(s);
        }
    }

    protected void onExpiration(Session session) {
        onChange(session);
    }

    protected void afterExpired(Session session) {
    }

    protected void onInvalidation(Session s, InvalidSessionException ise, SessionKey key) {
        if (ise instanceof ExpiredSessionException) {
            onExpiration(s, (ExpiredSessionException) ise, key);
            return;
        }
        log.trace("Session with id [{}] is invalid.", s.getId());
        try {
            onStop(s);
            notifyStop(s);
        } finally {
            afterStopped(s);
        }
    }

    protected void doValidate(Session session) throws InvalidSessionException {
        if (session instanceof ValidatingSession) {
            ((ValidatingSession) session).validate();
        } else {
            String msg = "The " + getClass().getName() + " implementation only supports validating " +
                    "Session implementations of the " + ValidatingSession.class.getName() + " interface.  " +
                    "Please either implement this interface in your session implementation or override the " +
                    AbstractValidatingSessionManager.class.getName() + ".doValidate(Session) method to perform validation.";
            throw new IllegalStateException(msg);
        }
    }

    /**
     * Subclass template hook in case per-session timeout is not based on
     * {@link org.apache.shiro.session.Session#getTimeout()}.
     * <p/>
     * <p>This implementation merely returns {@link org.apache.shiro.session.Session#getTimeout()}</p>
     *
     * @param session the session for which to determine session timeout.
     * @return the time in milliseconds the specified session may remain idle before expiring.
     */
    protected long getTimeout(Session session) {
        return session.getTimeout();
    }

    /**
     * 创建scheduler
     **/
    protected SessionValidationScheduler createSessionValidationScheduler() {
        ExecutorServiceSessionValidationScheduler scheduler;

        if (log.isDebugEnabled()) {
            log.debug("No sessionValidationScheduler set.  Attempting to create default instance.");
        }
        // 注意：这个的this指的就是ValidatingSessionManager接口啦，前面分析过，调度作业的具体内容时由这个接口来提供的。
        scheduler = new ExecutorServiceSessionValidationScheduler(this);
        scheduler.setInterval(getSessionValidationInterval());
        if (log.isTraceEnabled()) {
            log.trace("Created default SessionValidationScheduler instance of type [" + scheduler.getClass().getName() + "].");
        }
        return scheduler;
    }

    /**
     * 具体的开启实现在这里
     **/
    protected synchronized void enableSessionValidation() {
        // 是否设置了scheduler，如果没有就创建一个
        SessionValidationScheduler scheduler = getSessionValidationScheduler();
        if (scheduler == null) {
            // 创建scheduler
            scheduler = createSessionValidationScheduler();
            setSessionValidationScheduler(scheduler);
        }
        // it is possible that that a scheduler was already created and set via 'setSessionValidationScheduler()'
        // but would not have been enabled/started yet
        if (!scheduler.isEnabled()) {
            if (log.isInfoEnabled()) {
                log.info("Enabling session validation scheduler...");
            }
            // 开启调度作业
            scheduler.enableSessionValidation();
            // 开启作业后的后置处理方法(钩子方法)
            afterSessionValidationEnabled();
        }
    }

    protected void afterSessionValidationEnabled() {
    }

    protected synchronized void disableSessionValidation() {
        beforeSessionValidationDisabled();
        SessionValidationScheduler scheduler = getSessionValidationScheduler();
        if (scheduler != null) {
            try {
                scheduler.disableSessionValidation();
                if (log.isInfoEnabled()) {
                    log.info("Disabled session validation scheduler.");
                }
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    String msg = "Unable to disable SessionValidationScheduler.  Ignoring (shutting down)...";
                    log.debug(msg, e);
                }
            }
            LifecycleUtils.destroy(scheduler);
            setSessionValidationScheduler(null);
        }
    }

    protected void beforeSessionValidationDisabled() {
    }

    public void destroy() {
        disableSessionValidation();
    }

    /**
     * @see ValidatingSessionManager#validateSessions()
     */
    public void validateSessions() {
        if (log.isInfoEnabled()) {
            log.info("Validating all active sessions...");
        }
        // 标志无效的Session个数
        int invalidCount = 0;

        // 获取所有有效的Session
        // 这是一个抽象方法。因为目前来说，也不知道Session存放在哪里，要从哪里获取呢？
        Collection<Session> activeSessions = getActiveSessions();

        // 遍历判断Session是否有效
        if (activeSessions != null && !activeSessions.isEmpty()) {
            for (Session s : activeSessions) {
                try {
                    //simulate a lookup key to satisfy the method signature.
                    //this could probably stand to be cleaned up in future versions:
                    SessionKey key = new DefaultSessionKey(s.getId());
                    validate(s, key);
                } catch (InvalidSessionException e) {
                    if (log.isDebugEnabled()) {
                        boolean expired = (e instanceof ExpiredSessionException);
                        String msg = "Invalidated session with id [" + s.getId() + "]" +
                                (expired ? " (expired)" : " (stopped)");
                        log.debug(msg);
                    }
                    invalidCount++;
                }
            }
        }

        if (log.isInfoEnabled()) {
            String msg = "Finished session validation.";
            if (invalidCount > 0) {
                msg += "  [" + invalidCount + "] sessions were stopped.";
            } else {
                msg += "  No sessions were stopped.";
            }
            log.info(msg);
        }
    }

    protected abstract Collection<Session> getActiveSessions();
}
