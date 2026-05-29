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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JaspiMessageInfoTest
{
    private static final String AUTH_REQUEST_KEY = "javax.servlet.http.isAuthenticationRequest";

    private final ServletRequest request = null;
    private final ServletResponse response = null;

    @Test
    public void testMandatoryKeyWhenMandatory()
    {
        JaspiMessageInfo info = new JaspiMessageInfo(request, response, true);

        assertThat(info.getMap().get(JaspiMessageInfo.MANDATORY_KEY), is("true"));
        assertTrue(info.isAuthMandatory());
    }

    @Test
    public void testMandatoryKeyAbsentWhenNotMandatory()
    {
        JaspiMessageInfo info = new JaspiMessageInfo(request, response, false);

        assertFalse(info.getMap().containsKey(JaspiMessageInfo.MANDATORY_KEY));
        assertNull(info.getMap().get(JaspiMessageInfo.MANDATORY_KEY));
        assertFalse(info.isAuthMandatory());
    }

    @Test
    public void testMandatoryKeyCanBeUpdatedThroughMap()
    {
        JaspiMessageInfo info = new JaspiMessageInfo(request, response, false);

        assertNull(info.getMap().put(JaspiMessageInfo.MANDATORY_KEY, "true"));
        assertTrue(info.isAuthMandatory());

        assertThat(info.getMap().remove(JaspiMessageInfo.MANDATORY_KEY), is("true"));
        assertFalse(info.isAuthMandatory());
    }

    @Test
    public void testAuthenticationRequestKeyCanBeUpdatedThroughMap()
    {
        JaspiMessageInfo info = new JaspiMessageInfo(request, response, false);

        assertNull(info.getMap().put(AUTH_REQUEST_KEY, "true"));
        assertThat(info.getMap().get(AUTH_REQUEST_KEY), is("true"));

        assertThat(info.getMap().remove(AUTH_REQUEST_KEY), is("true"));
        assertFalse(info.getMap().containsKey(AUTH_REQUEST_KEY));
    }

    @Test
    public void testAuthMethodFromMap()
    {
        JaspiMessageInfo info = new JaspiMessageInfo(request, response, true);

        info.getMap().put(JaspiMessageInfo.AUTH_METHOD_KEY, "CUSTOM");
        assertThat(info.getAuthMethod(), is("CUSTOM"));
    }
}
