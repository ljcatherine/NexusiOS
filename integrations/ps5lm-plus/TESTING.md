# Safe first test: PS5LM Plus Nexus controller

Before title verification/transfer, normalize `eboot.bin` and
`sce_module/libc.prx` to mode **0755**. Verify both modes after deployment,
in addition to raw SELF hashes. The title verifier rejects missing execute
bits and records file modes in its manifest. A valid binary hash does not
prove that the console can execute a file uploaded as 0644. For new test
builds, remove and reinstall the isolated title using supported operations;
preserve originals, rollback and shared model/settings files.

## PS5 title provisioning pin

Some observed title sandboxes return owner 0/link count 0 from an open file
and deny path-based status calls, even though the private credential's true
owner is 1. Do not reinterpret those values as verified filesystem ownership
or fix this by widening permissions.

For that measured PS5 context, the build recipe accepts an explicit
`NEXUS_PS5_CONTROL_PIN_HEADER` pointing to a regular, non-symlink, owner-owned
0600 header. Generate its `NEXUS_CONTROL_PROVISIONING_DIGEST` definition from
the SHA-256 of the strong bearer in Debian's verified private configuration,
never from the mutable console digest. Keep the header in an ignored private
build directory. It contains only the verifier digest, not the bearer; never
commit the header or transmit the raw bearer to the console.

An explicitly pinned PS5 build requires the exact canonical 72-byte private
credential record and matching embedded digest on **every** startup. Only
the observed effective-UID 1 / file-UID 0 / zero-link context can use the pin
instead of unverifiable owner metadata, and it additionally requires exact
0600 mode with no special bits, a regular descriptor and no symlink. No
listener exists until validation completes. Missing/wrong pin configuration
fails compilation; a substituted or malformed file fails startup. Unpinned
builds keep the existing ownership checks. HTTP still requires the raw bearer;
the digest is never a bearer credential.

The pin establishes approved credential identity, not actual file ownership
or confidentiality. Its trust boundary includes reviewed build inputs and
the installed executable. Changing the bearer requires a coordinated new pin
build, private file provisioning and gateway configuration; old rollback
executables retain their old pin. The build always recompiles the controller
with the explicitly selected flags; do not reuse stale controller objects or
auto-discover an old header. Inspect the actual patched build recipe used.

The experimental PS5-native build has passed **offline** inspection and a minimal
PS5 hardware startup and inference test; **controller switching and Nexus iOS
integration remain untested**. The locally verified
test archive is `build/PS5LM-Nexus-Test-PPSA99742.zip`, with its `.sha256`
sidecar and `build/ps5lm-nexus-test-PPSA99742/manifest.json`. Follow this
checklist before installing or launching that package.

## Stage and inspect before touching the console

1. Build from the pinned `integrations/ps5lm-plus/clone-nexus-fork.sh` clone;
   avoid the original title ID **PPSA99581**. In the ignored test clone,
   run `prepare-test-identity.py` with a distinct, owner-verified unused
   nine-character `PPSA#####` title ID **before** invoking the builder.
2. Build the PS5 title using the upstream PS5_Vulkan cross-toolchain and
   its verified SDK, RADV release archive, native-tool and OpenGL files.
   Preserve the build logs. Do not substitute any unsigned host executable
   or empty DLL/archive for a required PS5 dependency.
3. Verify `build/app-ps5/title/<TEST_ID>` with `verify-test-title.py`.
   Save the manifest and SHA-256 hash alongside the package. A passing file
   validator is **not** a real PS5 hardware/firmware test.

   The current ZIP uses the provisional test ID **PPSA99742**. Confirm that
   this ID is genuinely unused on the target console before installation; if
   not, regenerate the package with another distinct ID and reverify it.

## Preserve working PS5LM Plus

1. Before transferring anything, back up the installed original
   `PPSA99581` title folder **and** `/data/PS5LM`, or the corresponding
   `/download0/PS5LM` sandbox state (settings, model.txt, model list,
   downloads and any conversations). Check that backup content and size are
   plausible before continuing. Avoid copying huge GGUF files unless needed;
   record their exact locations so they remain available to restore.
2. Test under a **different title ID**. This protects the original title
   files, **not** the global model/settings directory. Both application
   variants can still write `/data/PS5LM`; do not run both variants at once
   and never perform a model switch until state is backed up.
3. Keep the original files and title install intact. Launch and test the
   experimental title only after confirming that the chosen ID is unused.

## Start with the safest network configuration

1. Without `nexus-control.token`, the controller must remain **disabled**.
   Test this first. The controller never replaces llama-server on port 8081.
2. Create a *separate* random 32–128-character token on a trusted machine.
   Store only its `sha256:<64 lowercase hex digits>` digest in
   `nexus-control.token` with mode 0600 (or stricter); never place the raw
   token on the console. Store client-side copies in the Debian gateway's
   owner-only config and Nexus's iOS Keychain; never commit or log them.
3. The controller defaults to **127.0.0.1:8082**. Only create the
   `nexus-control.lan` opt-in marker when a protected private network/gateway
   and firewall policy are ready. Port 8082 is **HTTP without TLS** and must
   not be exposed to the internet or shared with untrusted Wi-Fi devices.
   **Current owner policy:** FTP :2121 and payload loader :9021 are accepted
   risks on the owner's trusted private LAN. Their LAN reachability does not
   alone block further experimental controller work. Hash storage mitigates
   simple FTP token disclosure, but FTP writes/loader code execution/plaintext
   interception remain possible; no network probe proves router WAN safety.
   Verify router mappings separately, preserve the original title and rollback,
   and never forward these services or unauthenticated management publicly.
   Dedicated controller authentication and the 401/200 checks below remain
   mandatory before model switching. Do not provision real console settings
   without authorized experimental-title preparation.

4. From a trusted client through the approved authenticated/private ingress,
   verify unauthorized requests return HTTP 401, and authenticated
   `/v1/nexus/status` and `/v1/nexus/models` reflect **actual** installed
   PS5 models. Confirm IDs are 16 lowercase hex characters.
5. Test a model switch only after saving ongoing conversations. `POST`
   `/v1/nexus/models/<id>/load` returning HTTP 202 means **queued**, not
   loaded; the native app restarts to reclaim GPU memory. Poll status until
   it reports the correct model as ready. A failed restart should expose
   `restart_failed`, rather than blocking subsequent requests forever.
6. Test Nexus native iOS controls and separately configured workspace
   bridges only after both sides authenticate successfully. Debian and NixOS
   agents are separate processes and must use distinct bearer tokens and
   explicit allowlisted roots. Workspaces are read-only by default; managed edits and fixed-profile commands require their separate grants, human review and explicit execution.

## Rollback

Stop the experimental title. Preserve logs, especially `app.log` and
`llama.log`; disable the experimental API by removing its token/opt-in marker
from the test state, restore the original PS5LM settings from the verified
backup if changed, then launch the original title. Do **not** delete or
overwrite the original `PPSA99581` binary as part of the test.

Nexus source changes and host tests are tracked in the Git repository; PS5
console acceptance and Vulkan inference behavior must be measured on the
actual device before labeling the new build production-ready.
