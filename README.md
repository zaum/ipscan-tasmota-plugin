# Tasmota Plugin for Angry IP Scanner

Queries Tasmota devices on your network and displays their friendly name (or device name) as a scan column.

## Installation

1. **Build** the plugin jar:
   ```
   ./gradlew build
   ```
   The jar is created at `build/libs/ipscan-tasmota-plugin-1.0.0.jar`.

2. **Copy** the jar into Angry IP Scanner's `plugins/` directory:
   - **Windows**: `%APPDATA%\Angry IP Scanner\plugins\`
   - **Linux / macOS**: `~/.angryip/plugins/`
   - *(Create the `plugins/` folder if it doesn't exist.)*

3. **Restart** Angry IP Scanner. The *Tasmota name* column will appear in the fetcher list.
