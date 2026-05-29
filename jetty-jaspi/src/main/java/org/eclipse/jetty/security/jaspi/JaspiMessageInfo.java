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

import java.util.HashMap;
import java.util.Map;
import javax.security.auth.message.MessageInfo;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Almost an implementation of jaspi MessageInfo.
 */
public class JaspiMessageInfo implements MessageInfo
{
    public static final String MANDATORY_KEY = "javax.security.auth.message.MessagePolicy.isMandatory";
    public static final String AUTH_METHOD_KEY = "javax.servlet.http.authType";
    public static final String AUTH_REQUEST_KEY = "javax.servlet.http.isAuthenticationRequest";
    private ServletRequest request;
    private ServletResponse response;
    private final Map<String, Object> map = new HashMap<>();

    public JaspiMessageInfo(ServletRequest request, ServletResponse response, boolean isAuthMandatory)
    {
        this.request = request;
        this.response = response;
        //JASPI 3.8.1
        setAuthMandatory(isAuthMandatory);
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Map getMap()
    {
        return map;
    }

    @Override
    public Object getRequestMessage()
    {
        return request;
    }

    @Override
    public Object getResponseMessage()
    {
        return response;
    }

    @Override
    public void setRequestMessage(Object request)
    {
        this.request = (ServletRequest)request;
    }

    @Override
    public void setResponseMessage(Object response)
    {
        this.response = (ServletResponse)response;
    }

    public String getAuthMethod()
    {
        return (String)map.get(AUTH_METHOD_KEY);
    }

    public boolean isAuthMandatory()
    {
        return "true".equals(map.get(MANDATORY_KEY));
    }

    public void setAuthMandatory(boolean isAuthMandatory)
    {
        setBooleanMapValue(MANDATORY_KEY, isAuthMandatory);
    }

    public boolean isAuthenticationRequest()
    {
        return "true".equals(map.get(AUTH_REQUEST_KEY));
    }

    public void setAuthenticationRequest(boolean isAuthenticationRequest)
    {
        setBooleanMapValue(AUTH_REQUEST_KEY, isAuthenticationRequest);
    }

    private void setBooleanMapValue(String key, boolean value)
    {
        if (value)
            map.put(key, "true");
        else
            map.remove(key);
    }
}
