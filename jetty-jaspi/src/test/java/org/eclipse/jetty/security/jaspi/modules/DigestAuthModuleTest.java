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

package org.eclipse.jetty.security.jaspi.modules;

import java.lang.reflect.Proxy;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.security.jaspi.JaspiMessageInfo;
import org.eclipse.jetty.security.jaspi.callback.CredentialValidationCallback;
import org.eclipse.jetty.util.TypeUtil;
import org.eclipse.jetty.util.security.Credential;
import org.eclipse.jetty.util.security.Password;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DigestAuthModuleTest
{
    private static final String REALM = "test";
    private static final String USER = "utf8user";
    // @checkstyle-disable-check : AvoidEscapedUnicodeCharactersCheck
    private static final String PASSWORD = "\u03B1\u03B2password";
    // @checkstyle-enable-check : AvoidEscapedUnicodeCharactersCheck
    private static final String NONCE_COUNT = "00000001";
    private static final String CLIENT_NONCE = "cnonce";
    private static final String URI = "/ctx/secure";

    @Test
    public void testUtf8PasswordIsAccepted() throws Exception
    {
        AuthenticationState state = new AuthenticationState(new Password(PASSWORD));
        DigestAuthModule module = new DigestAuthModule(state.callbackHandler, REALM);

        String challenge = challenge(module, state);
        assertTrue(challenge.contains("charset=UTF-8"));
        String nonce = nonce(challenge);
        String authorization = authorization(nonce, USER, PASSWORD, StandardCharsets.UTF_8);

        AuthStatus status = validate(module, state, authorization);
        assertTrue(state.validationCalled);
        assertTrue(state.validationResult);
        assertEquals(AuthStatus.SUCCESS, status);
    }

    @Test
    public void testStaleChallengeSeparatesCharsetParameter() throws Exception
    {
        AuthenticationState state = new AuthenticationState(new Password(PASSWORD));
        DigestAuthModule module = new DigestAuthModule(state.callbackHandler, REALM);
        module.useStale = true;

        String challenge = challenge(module, state);

        assertTrue(challenge.contains("charset=UTF-8, stale=false"));
    }

    private static String challenge(DigestAuthModule module, AuthenticationState state) throws Exception
    {
        validate(module, state, null);
        return state.challenge;
    }

    private static AuthStatus validate(DigestAuthModule module, AuthenticationState state, String authorization) throws Exception
    {
        HttpServletRequest request = (HttpServletRequest)Proxy.newProxyInstance(
            DigestAuthModuleTest.class.getClassLoader(),
            new Class<?>[]{HttpServletRequest.class},
            (proxy, method, args) ->
            {
                if ("getHeader".equals(method.getName()) && HttpHeader.AUTHORIZATION.asString().equals(args[0]))
                    return authorization;
                if ("getMethod".equals(method.getName()))
                    return "GET";
                if ("getContextPath".equals(method.getName()))
                    return "/ctx";
                return defaultValue(method.getReturnType());
            });
        MessageInfo messageInfo = new JaspiMessageInfo(request, state.response, true);
        return module.validateRequest(messageInfo, new Subject(), new Subject());
    }

    private static String authorization(String nonce, String user, String password, Charset charset) throws Exception
    {
        String response = digest("GET", URI, CLIENT_NONCE, user, REALM, password, nonce, NONCE_COUNT, "auth", charset);
        return "Digest username=\"" + user + "\", realm=\"" + REALM + "\", nonce=\"" + nonce + "\", uri=\"" + URI +
            "\", algorithm=MD5, response=\"" + response + "\", qop=auth, nc=" + NONCE_COUNT + ", cnonce=\"" + CLIENT_NONCE + "\"";
    }

    private static String digest(String method, String uri, String cnonce, String user, String realm, String password, String nonce, String nc, String qop, Charset charset) throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update((user + ":" + realm + ":" + password).getBytes(charset));
        byte[] ha1 = md.digest();
        md.reset();
        md.update((method + ":" + uri).getBytes(charset));
        byte[] ha2 = md.digest();
        md.reset();
        md.update((TypeUtil.toString(ha1, 16) + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + TypeUtil.toString(ha2, 16)).getBytes(charset));
        return TypeUtil.toString(md.digest(), 16);
    }

    private static String nonce(String challenge)
    {
        int start = challenge.indexOf("nonce=\"") + 7;
        return challenge.substring(start, challenge.indexOf('"', start));
    }

    private static Object defaultValue(Class<?> type)
    {
        if (!type.isPrimitive())
            return null;
        if (type == Boolean.TYPE)
            return false;
        if (type == Byte.TYPE)
            return (byte)0;
        if (type == Short.TYPE)
            return (short)0;
        if (type == Integer.TYPE)
            return 0;
        if (type == Long.TYPE)
            return 0L;
        if (type == Float.TYPE)
            return 0F;
        if (type == Double.TYPE)
            return 0D;
        if (type == Character.TYPE)
            return (char)0;
        return null;
    }

    private static class AuthenticationState
    {
        private final Credential storedCredential;
        private final CallbackHandler callbackHandler;
        private final HttpServletResponse response;
        private String challenge;
        private boolean validationCalled;
        private boolean validationResult;

        private AuthenticationState(Credential storedCredential)
        {
            this.storedCredential = storedCredential;
            callbackHandler = callbacks ->
            {
                for (Callback callback : callbacks)
                {
                    CredentialValidationCallback validation = (CredentialValidationCallback)callback;
                    validationCalled = true;
                    validationResult = validation.getCredential().check(this.storedCredential);
                    validation.setResult(validationResult);
                }
            };
            response = (HttpServletResponse)Proxy.newProxyInstance(
                DigestAuthModuleTest.class.getClassLoader(),
                new Class<?>[]{HttpServletResponse.class},
                (proxy, method, args) ->
                {
                    if ("setHeader".equals(method.getName()) && HttpHeader.WWW_AUTHENTICATE.asString().equals(args[0]))
                        challenge = (String)args[1];
                    return defaultValue(method.getReturnType());
                });
        }

    }
}
