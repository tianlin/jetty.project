//
//  ========================================================================
//  Copyright (c) 1995-2022 Mort Bay Consulting Pty Ltd and others.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.security.jaspi;

import java.lang.reflect.Proxy;
import java.security.Principal;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.Queue;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.authentication.DeferredAuthentication;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Request;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class JaspiAuthenticatorTest
{
    private static final String AUTH_REQUEST_KEY = "javax.servlet.http.isAuthenticationRequest";

    @Test
    public void testMandatoryRequestIsNotAuthenticationRequest() throws Exception
    {
        CapturingServerAuthContext context = new CapturingServerAuthContext();
        JaspiAuthenticator authenticator = newAuthenticator(context, new ServletCallbackHandler(null));
        Request request = new Request(null, null);

        authenticator.validateRequest(request, newResponse(), true);

        assertThat(context.lastMessageInfo.getMap().get(JaspiMessageInfo.MANDATORY_KEY), is("true"));
        assertFalse(context.lastMessageInfo.getMap().containsKey(AUTH_REQUEST_KEY));
    }

    @Test
    public void testLazyRequestIsNotMandatoryOrAuthenticationRequest() throws Exception
    {
        CapturingServerAuthContext context = new CapturingServerAuthContext();
        JaspiAuthenticator authenticator = newAuthenticator(context, new ServletCallbackHandler(null));
        Request request = new Request(null, null);

        authenticator.validateRequest(request, newResponse(), false);

        assertFalse(context.lastMessageInfo.getMap().containsKey(JaspiMessageInfo.MANDATORY_KEY));
        assertFalse(context.lastMessageInfo.getMap().containsKey(AUTH_REQUEST_KEY));
    }

    @Test
    public void testDeferredSilentAuthenticationIsNotMandatoryOrAuthenticationRequest()
    {
        CapturingServerAuthContext context = new CapturingServerAuthContext();
        JaspiAuthenticator authenticator = newAuthenticator(context, new ServletCallbackHandler(null));
        Request request = new Request(null, null);
        request.setAuthentication(new DeferredAuthentication(authenticator));

        request.getAuthType();

        assertFalse(context.lastMessageInfo.getMap().containsKey(JaspiMessageInfo.MANDATORY_KEY));
        assertFalse(context.lastMessageInfo.getMap().containsKey(AUTH_REQUEST_KEY));
    }

    @Test
    public void testProgrammaticAuthenticationIsMandatoryAuthenticationRequest() throws Exception
    {
        CapturingServerAuthContext context = new CapturingServerAuthContext();
        JaspiAuthenticator authenticator = newAuthenticator(context, new ServletCallbackHandler(null));
        Request request = new Request(null, null);
        request.setAuthentication(new DeferredAuthentication(authenticator));

        authenticator.validateRequest(request, newResponse(), true);

        assertThat(context.lastMessageInfo.getMap().get(JaspiMessageInfo.MANDATORY_KEY), is("true"));
        assertThat(context.lastMessageInfo.getMap().get(AUTH_REQUEST_KEY), is("true"));
    }

    @Test
    public void testStaleCallerPrincipalCallbackIsClearedBeforeValidateRequest() throws Exception
    {
        CapturingServerAuthContext context = new CapturingServerAuthContext();
        ServletCallbackHandler callbackHandler = new ServletCallbackHandler(null);
        JaspiAuthenticator authenticator = newAuthenticator(context, callbackHandler);
        Subject staleSubject = new Subject();
        context.actions.add((messageInfo, clientSubject, handler) -> AuthStatus.SUCCESS);
        callbackHandler.handle(new Callback[]
            {new CallerPrincipalCallback(staleSubject, namedPrincipal("stale"))});

        Authentication authentication = authenticator.validateRequest(new Request(null, null), newResponse(), true);

        assertThat(authentication, is(Authentication.UNAUTHENTICATED));
    }

    @Test
    public void testJaspiAuthTypeIsPropagatedToUserAuthentication() throws Exception
    {
        CapturingServerAuthContext context = new CapturingServerAuthContext();
        context.actions.add((messageInfo, clientSubject, callbackHandler) ->
        {
            messageInfo.getMap().put(JaspiMessageInfo.AUTH_METHOD_KEY, "TEST-JASPI");
            callbackHandler.handle(new Callback[]
                {
                    new CallerPrincipalCallback(clientSubject, namedPrincipal("user")),
                    new GroupPrincipalCallback(clientSubject, new String[]{"users"})
                });
            return AuthStatus.SUCCESS;
        });
        JaspiAuthenticator authenticator = newAuthenticator(context, new ServletCallbackHandler(null));

        Authentication authentication = authenticator.validateRequest(new Request(null, null), newResponse(), true);

        assertThat(authentication, instanceOf(Authentication.User.class));
        assertThat(((Authentication.User)authentication).getAuthMethod(), is("TEST-JASPI"));
    }

    private static JaspiAuthenticator newAuthenticator(CapturingServerAuthContext context, ServletCallbackHandler callbackHandler)
    {
        context.callbackHandler = callbackHandler;
        return new JaspiAuthenticator(new TestServerAuthConfig(context), null, callbackHandler, new Subject(),
            true, new DefaultIdentityService());
    }

    private static Principal namedPrincipal(String name)
    {
        return () -> name;
    }

    private static HttpServletResponse newResponse()
    {
        return (HttpServletResponse)Proxy.newProxyInstance(
            JaspiAuthenticatorTest.class.getClassLoader(),
            new Class<?>[]{HttpServletResponse.class},
            (proxy, method, args) ->
            {
                Class<?> returnType = method.getReturnType();
                if (returnType == Boolean.TYPE)
                    return false;
                if (returnType == Integer.TYPE)
                    return 0;
                if (returnType == Long.TYPE)
                    return 0L;
                return null;
            });
    }

    private interface ValidationAction
    {
        AuthStatus validate(MessageInfo messageInfo, Subject clientSubject, ServletCallbackHandler callbackHandler) throws Exception;
    }

    private static class CapturingServerAuthContext implements ServerAuthContext
    {
        private final Queue<ValidationAction> actions = new ArrayDeque<>();
        private ServletCallbackHandler callbackHandler;
        private JaspiMessageInfo lastMessageInfo;

        @Override
        public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException
        {
            lastMessageInfo = (JaspiMessageInfo)messageInfo;
            ValidationAction action = actions.poll();
            if (action == null)
                return AuthStatus.SEND_FAILURE;

            try
            {
                return action.validate(messageInfo, clientSubject, callbackHandler);
            }
            catch (Exception e)
            {
                AuthException authException = new AuthException(e.getMessage());
                authException.initCause(e);
                throw authException;
            }
        }

        @Override
        public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject)
        {
            return AuthStatus.SEND_SUCCESS;
        }

        @Override
        public void cleanSubject(MessageInfo messageInfo, Subject subject)
        {
        }
    }

    private static class TestServerAuthConfig implements ServerAuthConfig
    {
        private final ServerAuthContext authContext;

        private TestServerAuthConfig(ServerAuthContext authContext)
        {
            this.authContext = authContext;
        }

        @Override
        public ServerAuthContext getAuthContext(String authContextID, Subject serviceSubject, Map properties)
        {
            return authContext;
        }

        @Override
        public String getAppContext()
        {
            return "test";
        }

        @Override
        public String getAuthContextID(MessageInfo messageInfo)
        {
            return "test";
        }

        @Override
        public String getMessageLayer()
        {
            return "HttpServlet";
        }

        @Override
        public boolean isProtected()
        {
            return true;
        }

        @Override
        public void refresh()
        {
        }
    }
}
