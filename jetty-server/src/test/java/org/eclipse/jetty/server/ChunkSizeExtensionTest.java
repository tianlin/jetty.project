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
//      The Apache License is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.handler.AbstractHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ChunkSizeExtensionTest
{
    private Server _server;
    private ServerConnector _connector;
    private final AtomicInteger _smuggled = new AtomicInteger();

    @AfterEach
    public void stop() throws Exception
    {
        if (_server != null)
            _server.stop();
    }

    @Test
    public void testQuotedChunkExtensionCrLfDoesNotSmuggleNextRequest() throws Exception
    {
        startServer();

        String request =
            "POST /chunk HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "1;a=\"\r\n" +
                "X\r\n" +
                "0\r\n" +
                "\r\n" +
                "GET /smuggled HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Connection: close\r\n" +
                "\r\n";

        String response;
        try (Socket socket = new Socket("localhost", _connector.getLocalPort()))
        {
            socket.setSoTimeout(3000);
            OutputStream output = socket.getOutputStream();
            output.write(request.getBytes(StandardCharsets.ISO_8859_1));
            output.flush();

            response = readAvailable(socket.getInputStream());
        }

        assertThat(_smuggled.get(), is(0));
        assertThat(response, not(containsString("smuggled")));
        assertTrue(countResponses(response) < 2, response);
        assertTrue(response.isEmpty() || response.contains(" 400 ") || !response.contains(" 200 "), response);
    }

    @Test
    public void testAdvisoryPoCDoesNotSmuggleNextRequest() throws Exception
    {
        startServer();

        String request =
            "POST /chunk HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "5;foo=\"bar\r\n" +
                "12345\r\n" +
                "0\r\n" +
                "\r\n" +
                "GET /smuggled HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Connection: close\r\n" +
                "\r\n";

        String response;
        try (Socket socket = new Socket("localhost", _connector.getLocalPort()))
        {
            socket.setSoTimeout(3000);
            OutputStream output = socket.getOutputStream();
            output.write(request.getBytes(StandardCharsets.ISO_8859_1));
            output.flush();

            response = readAvailable(socket.getInputStream());
        }

        assertThat(_smuggled.get(), is(0));
        assertThat(response, not(containsString("smuggled")));
        assertTrue(countResponses(response) < 2, response);
        assertTrue(response.isEmpty() || response.contains(" 400 ") || !response.contains(" 200 "), response);
    }

    private void startServer() throws Exception
    {
        _server = new Server();
        _connector = new ServerConnector(_server);
        _connector.setPort(0);
        _server.addConnector(_connector);
        _server.setHandler(new AbstractHandler()
        {
            @Override
            public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
            {
                if ("/chunk".equals(target))
                {
                    baseRequest.setHandled(true);
                    drain(request.getInputStream());
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.getWriter().write("chunk");
                }
                else if ("/smuggled".equals(target))
                {
                    baseRequest.setHandled(true);
                    _smuggled.incrementAndGet();
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.getWriter().write("smuggled");
                }
            }
        });
        _server.start();
    }

    private static void drain(InputStream input) throws IOException
    {
        byte[] buffer = new byte[512];
        while (input.read(buffer) >= 0)
        {
            // Drain request content so the connection parser must validate the chunk line.
        }
    }

    private static String readAvailable(InputStream input) throws IOException
    {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (true)
        {
            try
            {
                int read = input.read(buffer);
                if (read < 0)
                    break;
                output.write(buffer, 0, read);
            }
            catch (SocketTimeoutException x)
            {
                break;
            }
        }
        return output.toString(StandardCharsets.ISO_8859_1.name());
    }

    private static int countResponses(String response)
    {
        int count = 0;
        int index = 0;
        while (true)
        {
            index = response.indexOf("HTTP/1.1 ", index);
            if (index < 0)
                return count;
            count++;
            index += "HTTP/1.1 ".length();
        }
    }
}
