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

package org.eclipse.jetty.server;

import org.eclipse.jetty.http.HttpCompliance;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class HttpConfigurationTest
{
    @Test
    public void testDefaultAndCopyHttpCompliance()
    {
        HttpConfiguration configuration = new HttpConfiguration();
        assertEquals(HttpCompliance.RFC7230, configuration.getHttpCompliance());

        configuration.setHttpCompliance(HttpCompliance.RFC2616);
        HttpConfiguration copy = new HttpConfiguration(configuration);
        assertEquals(HttpCompliance.RFC2616, copy.getHttpCompliance());
    }

    @Test
    public void testConnectionFactorySynchronizesHttpCompliance()
    {
        HttpConfiguration configuration = new HttpConfiguration();
        HttpConnectionFactory factory = new HttpConnectionFactory(configuration, HttpCompliance.RFC2616);
        assertEquals(HttpCompliance.RFC2616, configuration.getHttpCompliance());
        assertEquals(HttpCompliance.RFC2616, factory.getHttpCompliance());

        factory.setHttpCompliance(HttpCompliance.RFC7230);
        assertEquals(HttpCompliance.RFC7230, configuration.getHttpCompliance());
        assertEquals(HttpCompliance.RFC7230, factory.getHttpCompliance());
    }
}
