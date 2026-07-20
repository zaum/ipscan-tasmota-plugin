/*
  TasmotaFetcher - an Angry IP Scanner plugin that queries Tasmota devices
  for their FriendlyName (or DeviceName) via the HTTP JSON API.

  Licensed under GPLv2.
 */
package org.angryip.plugins.tasmota;

import net.azib.ipscan.core.ScanningSubject;
import net.azib.ipscan.fetchers.Fetcher;
import net.azib.ipscan.fetchers.FetcherRegistry;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.Thread.currentThread;


/**
 * Queries http://<ip>/cm?cmnd=Status%200 on hosts with an open web port and
 * extracts the device's FriendlyName[0] (falling back to DeviceName).
 *
 * The fetcher is safe to run against any host: if the port is closed, the
 * device is not a Tasmota, or the response cannot be parsed, it simply
 * returns null without throwing.
 */
public class TasmotaFetcher implements Fetcher {

	// The open-ports parameter key is set by PortsFetcher under this literal
	// value (it is package-private there, so we reference it directly).
	private static final String PARAMETER_OPEN_PORTS = "openPorts";

	public static final String ID = "fetcher.tasmota";

	public TasmotaFetcher(FetcherRegistry registry) {
		registerIntoRegistry(registry);
	}

	private void registerIntoRegistry(FetcherRegistry registry) {
		if (registry == null) return;
		try {
			Field field = FetcherRegistry.class.getDeclaredField("registeredFetchers");
			field.setAccessible(true);
			Map<String, Fetcher> map = (Map<String, Fetcher>) field.get(registry);
			if (map.containsKey(getId())) return;
			Map<String, Fetcher> newMap = new LinkedHashMap<>(map);
			newMap.put(getId(), this);
			field.set(registry, java.util.Collections.unmodifiableMap(newMap));
		}
		catch (Exception ignored) {
		}
	}

	private static final int DEFAULT_PORT = 80;
	private static final String REQUEST =
			"GET /cm?cmnd=Status%200 HTTP/1.0\r\n\r\n";

	// Matches "FriendlyName":["name"] or "FriendlyName":"name"
	private static final Pattern FRIENDLY = Pattern.compile(
			"\"FriendlyName\"\\s*:\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|\\[\\s*\"(?:[^\"\\\\]|\\\\.)*\"\\s*\\])");
	// Matches "DeviceName":"name"
	private static final Pattern DEVICE = Pattern.compile(
			"\"DeviceName\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
	// Strips the surrounding quotes / array brackets from a captured value
	private static final Pattern QUOTED = Pattern.compile("\"([^\"]*)\"");

	@Override
	public String getId() {
		return ID;
	}

	@Override
	public String getName() {
		return "Tasmota name";
	}

	@Override
	public String getFullName() {
		return getName();
	}

	@Override
	public String getInfo() {
		return "Friendly name of a Tasmota device";
	}

	@Override
	@SuppressWarnings("rawtypes")
	public Class getPreferencesClass() {
		return null;
	}

	@Override
	public Object scan(ScanningSubject subject) {
		var portIterator = getPortIterator(subject);
		while (portIterator.hasNext() && !currentThread().isInterrupted()) {
			int port = portIterator.next();
			try (var socket = new Socket()) {
				socket.connect(new InetSocketAddress(subject.getAddress(), port), subject.getAdaptedPortTimeout());
				socket.setTcpNoDelay(true);
				socket.setSoTimeout(subject.getAdaptedPortTimeout() * 2);

				socket.getOutputStream().write(REQUEST.getBytes(StandardCharsets.US_ASCII));

				var in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
				StringBuilder body = new StringBuilder();
				String line;
				boolean headersDone = false;
				while ((line = in.readLine()) != null) {
					if (!headersDone) {
						if (line.isEmpty()) headersDone = true;
						continue;
					}
					body.append(line);
				}

				String name = extractName(body.toString());
				if (name != null && !name.isEmpty()) {
					return name;
				}
			}
			catch (Exception ignored) {
				// closed port, timeout, reset, non-Tasmota response, etc.
			}
		}
		return null;
	}

	private String extractName(String body) {
		Matcher fm = FRIENDLY.matcher(body);
		if (fm.find()) {
			String captured = fm.group(1);
			Matcher qm = QUOTED.matcher(captured);
			if (qm.find()) {
				String name = qm.group(1);
				if (name != null && !name.isEmpty()) return name;
			}
		}
		Matcher dm = DEVICE.matcher(body);
		if (dm.find()) {
			String name = dm.group(1);
			if (name != null && !name.isEmpty()) return name;
		}
		return null;
	}

	private Iterator<Integer> getPortIterator(ScanningSubject subject) {
		@SuppressWarnings("unchecked")
		var openPorts = (SortedSet<Integer>) subject.getParameter(PARAMETER_OPEN_PORTS);
		if (openPorts != null && !openPorts.isEmpty()) {
			SortedSet<Integer> ports = new TreeSet<>(openPorts);
			ports.add(DEFAULT_PORT);
			return ports.iterator();
		}
		if (subject.isAnyPortRequested()) {
			return subject.requestedPortsIterator();
		}
		// No open web port is known for this host and none were requested:
		// probing every IP would only slow the scan down, so skip it.
		return java.util.Collections.<Integer>emptyIterator();
	}

	@Override
	public void init() {
	}

	@Override
	public void cleanup() {
	}
}
