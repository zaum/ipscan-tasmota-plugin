/*
  TasmotaFetcher - an Angry IP Scanner plugin that queries Tasmota devices
  for their FriendlyName (or DeviceName) via the HTTP JSON API.

  Licensed under GPLv2.
 */
package org.angryip.plugins.tasmota;

import net.azib.ipscan.core.Plugin;
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
public class TasmotaFetcher implements Fetcher, Plugin {

	// The open-ports parameter key is set by PortsFetcher under this literal
	// value (it is package-private there, so we reference it directly).
	private static final String PARAMETER_OPEN_PORTS = "openPorts";

	public static final String ID = "fetcher.tasmota";

	// Dedicated preference flag recording the user's explicit choice, so an
	// enabled fetcher survives restarts despite the core app reading the
	// selected-fetchers list before plugins are loaded.
	private static final String DISABLED_KEY = "fetcher.tasmota.disabled";

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

			// Track explicit enable/disable made through the Fetchers dialog so we
			// can tell "user turned it off" apart from "selection was lost on restart".
			registry.addListener(reg2 -> persistEnabledState(reg2));

			restoreSelectionIfNeeded(registry);
		}
		catch (Exception ignored) {
		}
	}

	/**
	 * Called whenever the selected-fetchers list changes (i.e. the user saved the
	 * Fetchers dialog). Records the user's explicit choice in a dedicated flag so
	 * that an enabled Tasmota survives application restarts.
	 */
	private void persistEnabledState(FetcherRegistry registry) {
		try {
			java.util.prefs.Preferences prefs = getPreferences(registry);
			if (prefs == null) return;
			boolean enabled = registry.getSelectedFetchers().stream()
					.anyMatch(f -> getId().equals(f.getId()));
			if (enabled) {
				prefs.remove(DISABLED_KEY);
			}
			else {
				prefs.put(DISABLED_KEY, "true");
			}
		}
		catch (Exception ignored) {
		}
	}

	/**
	 * The selected-fetchers list is read from Java Preferences at registry
	 * construction time, before plugins are loaded. If the user had previously
	 * enabled this fetcher (or it was enabled but its selection got lost on a
	 * previous restart), re-apply that selection now that we are registered, and
	 * re-persist it so the corruption cycle cannot drop it again.
	 */
	@SuppressWarnings("unchecked")
	private void restoreSelectionIfNeeded(FetcherRegistry registry) {
		try {
			java.util.prefs.Preferences prefs = getPreferences(registry);
			if (prefs == null) return;

			// User explicitly turned the fetcher off -> respect that.
			if (prefs.get(DISABLED_KEY, null) != null) return;

			String saved = prefs.get("selectedFetchers", null);
			boolean wasEnabled = saved != null
					&& java.util.Arrays.asList(saved.split("###")).contains(getId());
			// Nothing in the preference and never explicitly disabled: keep it off
			// (don't force-enable on a fresh install where the user never chose it).
			if (!wasEnabled) return;

			Field selectedField = FetcherRegistry.class.getDeclaredField("selectedFetchers");
			selectedField.setAccessible(true);
			Map<String, Fetcher> selected = (Map<String, Fetcher>) selectedField.get(registry);
			if (selected.containsKey(getId())) return;

			Map<String, Fetcher> newSelected = new LinkedHashMap<>(selected);
			newSelected.put(getId(), this);
			selectedField.set(registry, java.util.Collections.unmodifiableMap(newSelected));

			// Re-persist so the selection cannot be lost again on the next restart.
			registry.updateSelectedFetchers(newSelected.keySet().toArray(new String[0]));
		}
		catch (Exception ignored) {
		}
	}

	private static java.util.prefs.Preferences getPreferences(FetcherRegistry registry) {
		try {
			Field prefsField = FetcherRegistry.class.getDeclaredField("preferences");
			prefsField.setAccessible(true);
			return (java.util.prefs.Preferences) prefsField.get(registry);
		}
		catch (Exception e) {
			return null;
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
