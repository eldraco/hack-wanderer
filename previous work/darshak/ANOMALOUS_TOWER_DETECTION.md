# Darshak: How It Detects “Anomalous” (Suspicious) Cell Towers

This document describes, from the code, the exact methods Darshak uses to detect suspicious/anomalous cell towers. In this codebase, “anomalous tower” detection is implemented as “**GSM broadcast profile parameters changed**” (and separately, “silent SMS received”).

Repo analyzed: `darshakframework/darshak` (Android app under `src/`).

## High-Level Flow (Where Detection Happens)

1. `com.darshak.service.DarshakService.lookForSecurityCodes()` locates modem/baseband log files (`Utils.searchLogFile()`), reads them as raw bytes (`LogFileReader.readFile(...)`), and scans those bytes for configured “packet” patterns (`PacketReader.generateResult(...)`).
2. For tower anomaly detection, it specifically scans for **profile parameters**:
   - `sPacketReader.generateResult(filteredByteSeq, Constants.PROFILE_PARAMS)`
3. It then compares the extracted “profile parameter” attributes against a local DB of previously observed values:
   - `DarshakService.beginProfileParamComparison(profileParams)`
   - `ProfileParamsComparisonTask.doInBackground(...)`
4. If *any* profile parameter attribute is new (not seen before), it triggers an Android notification:
   - `ProfileParamsComparisonTask.setNotification(...)`

## What Data It Captures

Darshak captures data by:

1. Reading **raw modem log bytes** from files returned by `Utils.searchLogFile()`:
   - `com.darshak.packetreader.LogFileReader.readFile(File logFile)` returns `byte[]` of the entire file.
2. Extracting and storing “packets” and “packet attributes” in a local SQLite DB via `com.darshak.db.DarshakDBHelper`.

### Packet-level data captured

Every extracted “packet” is represented by:

- `PacketType` (integer ID, enum `com.darshak.constants.PacketType`)
- `hexCode` (string): the full matched byte sequence formatted as hex

In code, a packet is created in each formatter like:

- `new Packet(SYS_INFO_3, hexCode)` in `com.darshak.formatter.GSMSysInfoTypeThreeFormatter.formatPacket(...)`

### Profile parameter attribute-level data captured

For the “profile parameter changed” signal, Darshak captures *packet attributes* derived from **GSM System Information Type 3** (`PacketType.SYS_INFO_3`), as `PacketAttribute` objects:

- `packetAttrTypeId` (from `PacketAttributeType`, an enum)
- `hexCode` (the raw bytes for that attribute formatted as hex)
- `displayText` (human-readable rendering)

These are persisted in:

- Profile-param baseline table: `DarshakDBHelper.insertProfileParams(PacketAttribute)`
  - Stores `TYPE` (= `packetAttrTypeId`), `HEX_CODE` (= attribute hexCode), `DISPLAY_TXT` (= displayText).
- And also stored as normal log entries/packet attributes when profile packets are inserted:
  - `DarshakService.insertEntriesIfNotDuplicate(profileParams, ..., Event.PROFILE_PARAMS, ...)`

## The EXACT “Anomalous Tower” Detection Method

Darshak’s “tower anomaly” alert is **change detection** on the GSM System Information Type 3 broadcast parameters.

### Extraction: which packet is treated as “profile params”

The “profile parameter” scan type (`Constants.PROFILE_PARAMS`) maps to exactly one packet signature:

- `PacketConfigurator.getPacketsList(Constants.PROFILE_PARAMS, context)`
  - clears `sProfilePacketList`
  - adds `PacketConfigurator.sysInfoTypeThree(context)`

`sysInfoTypeThree(context)` builds a `PacketIdentificationDetails` for `PacketType.SYS_INFO_3` using:

- A base signature byte sequence `sysInfo3Bytes[]` (length 23)
- The device’s current operator code from `TelephonyManager.getNetworkOperator()` encoded into bytes and injected into offsets `[5]`, `[6]`, `[7]` of `sysInfo3Bytes`.
- A wildcard list `sysInfo3AnythingAllwdByts` allowing certain bytes in the signature to vary without breaking the match: indices
  - `[3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]`

The match window parameters passed into `PacketIdentificationDetails(...)` are:

- `frstFxdBytIndx = 0`
- `lstFxdBytIndx = 22`

In other words: Darshak scans the modem log byte stream for occurrences of a **GSM System Information Type 3** pattern that matches the current network operator and tolerates variability in the listed “anything allowed” byte positions.

### Decoding: which exact fields are extracted from SYS_INFO_3

When a SYS_INFO_3 packet is matched, it is decoded by:

- `com.darshak.formatter.GSMSysInfoTypeThreeFormatter.formatPacket(byte[] packetBytes)`

This formatter extracts the following PacketAttributes (byte offsets shown are the formatter’s `extract(packetBytes, start, end)` calls; `end` is inclusive in this codebase’s formatter convention):

1. `CELL_IDENTITY`:
   - bytes `3..5` (`getCellIdentity`)
2. `MOB_CNTRY_CODE` (MCC):
   - bytes `5..7` (`getMobCountryCode`) with nibble-swapping logic for display
3. `MOB_NW_CODE` (MNC):
   - bytes `7..8` (`getMobNwCode`) with nibble-swapping logic for display
4. `LOC_AREA_CODE` (LAC):
   - bytes `8..10` (`getLocationAreaCode`)
5. `MSCR`:
   - byte `10..11` (`getMSCR`) (interprets one bit to show Release ’98 vs ’99)
6. `CELL_OPTIONS` (PWRC boolean):
   - byte `13..14` (`getPWRCValue`) (bit mask `0x40`)
7. `CELL_OPTIONS` (Radio Link Timeout):
   - byte `13..14` (`getRadioLinkTimeout`) (low nibble mask `0x0F`)
8. `CELL_SELECTION_PARAMS` (RXLEV-ACCESS-MIN):
   - byte `15..16` (`getCellSelectionParameter`) (low 6 bits mask `0x3F`)

These extracted attributes are what Darshak calls “profile parameters”.

### Change detection: what exactly triggers the anomaly alert

Change detection is implemented in:

- `com.darshak.service.ProfileParamsComparisonTask.doInBackground(PacketAttribute... params)`

For each extracted `PacketAttribute`:

1. Check if it exists in the baseline DB table:
   - `DarshakDBHelper.isProfileParamPresent(packetAttr)`
   - Presence test is exact match on:
     - `TYPE == packetAttr.getPacketAttrTypeId()`
     - `HEX_CODE == packetAttr.getHexCode()`
2. If not present:
   - It is considered “changed” / “new”
   - The attribute is inserted into the baseline table:
     - `DarshakDBHelper.insertProfileParams(packetAttr)`
3. If at least one new attribute is found, a notification is raised via:
   - `ProfileParamsComparisonTask.publishProgress(...)`
   - `ProfileParamsComparisonTask.setNotification(...)`

So the anomaly rule is:

> Alert if any GSM SYS_INFO_3-derived profile attribute has a (typeId, hexCode) pair that has not been seen before on this device/database.

## Notes / Scope Clarification

- This repo’s “anomalous tower” signal is not a numerical score and does not triangulate tower locations. It is a **baseline-change detector** over a specific GSM broadcast message (System Information Type 3).
- Darshak also detects “silent SMS received” by scanning modem logs for specific SMS byte patterns (`PacketType.SILENT_SMS`) and shows a notification (`DarshakService.setSilentSMSNotification()`), but that is distinct from tower anomaly detection.

