/*
  TasmotaFetcherTest - verifies Tasmota name extraction against a mock server.
  Licensed under GPLv2.
 */
package org.angryip.plugins.tasmota;

import net.azib.ipscan.core.ScanningSubject;
import net.azib.ipscan.fetchers.FetcherRegistry;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class TasmotaFetcherTest {

	private TasmotaFetcher fetcher;
	private ServerSocket server;
	private int port;
	private final AtomicReference<String> responseBody = new AtomicReference<>("");

	@Before
	public void setUp() throws Exception {
		fetcher = new TasmotaFetcher(null);
		server = new ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"));
		port = server.getLocalPort();
		new Thread(() -> {
			try {
				while (!server.isClosed()) {
					try (Socket s = server.accept()) {
						// read and discard the request
						var in = s.getInputStream();
						int b;
						while ((b = in.read()) != -1 && in.available() > 0) { /* drain */ }
						var out = s.getOutputStream();
						var body = responseBody.get();
						var headers = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
								+ body.getBytes(StandardCharsets.UTF_8).length + "\r\n\r\n";
						out.write((headers + body).getBytes(StandardCharsets.UTF_8));
						out.flush();
					}
					catch (Exception ignored) {
						break;
					}
				}
			}
			catch (Exception ignored) {
			}
		}).start();
	}

	@After
	public void tearDown() throws Exception {
		server.close();
	}

	private ScanningSubject subjectWithOpenPort() throws Exception {
		var subject = new ScanningSubject(InetAddress.getByName("127.0.0.1"));
		var ports = new java.util.TreeSet<Integer>();
		ports.add(port);
		subject.setParameter("openPorts", ports);
		return subject;
	}

	@Test
	public void extractsFriendlyNameArray() throws Exception {
		responseBody.set("{\"Status\":{\"FriendlyName\":[\"furdo-izzo-AiYaTo-RGBCW\"],\"DeviceName\":\"x\"}}");
		assertEquals("furdo-izzo-AiYaTo-RGBCW", fetcher.scan(subjectWithOpenPort()));
	}

	@Test
	public void fallsBackToDeviceName() throws Exception {
		responseBody.set("{\"Status\":{\"FriendlyName\":[\"\"],\"DeviceName\":\"my-device\"}}");
		assertEquals("my-device", fetcher.scan(subjectWithOpenPort()));
	}

	@Test
	public void returnsNullForNonTasmotaResponse() throws Exception {
		responseBody.set("{\"some\":\"random json\"}");
		assertNull(fetcher.scan(subjectWithOpenPort()));
	}

	@Test
	public void returnsNullWhenNoOpenPort() throws Exception {
		// No open ports set on the subject -> fetcher should skip probing.
		var subject = new ScanningSubject(InetAddress.getByName("127.0.0.1"));
		assertNull(fetcher.scan(subject));
	}
}
