# Tkinter GUI for POSFramework

This change adds a full-featured Tkinter graphical interface to POSFramework, wrapping the existing CLI-driven recon, attack, MITM, credential harvesting, and printer exploitation engines in a tabbed dark-themed window. The GUI uses daemon threads for all engine operations, a queue-based logging pipeline for thread-safe display, and periodic database polling for table updates. The design gracefully degrades when scapy or tkinter are unavailable.

Watch for: thread-safety gaps in shared mutable state between daemon threads and the main loop (confirmed), no validation on user-supplied network inputs passed directly to engines (confirmed), `message_queue` is populated but never consumed (confirmed), and the refresh-interval setting change doesn't reschedule the existing `after` timer (confirmed).

**Verdict**: NEEDS_CHANGES

## High-level view

The GUI is a single 1691-line class (`POSFrameworkGUI`) that owns the Tk root, all engine references, and all state flags. Engines run in daemon threads that mutate shared instance variables (`self.recon_running`, `self.orchestrator`, etc.) without synchronization, relying on CPython's GIL for atomicity — a reasonable bet for boolean flags but dangerous for compound state transitions like stop-then-nullify sequences.

User inputs (BSSID, target IP, gateway IP) flow from `StringVar` entries directly into engine constructors with no format validation. A typo or malicious string reaches the network layer unfiltered. The MITM tab omits gateway-IP validation entirely — it passes an empty-string fallback as `None`, but only after `.strip()`, meaning whitespace-only input becomes `None` silently.

The `message_queue` is a thread-safe conduit intended to signal state transitions (recon_started, attack_stopped, etc.) back to the main thread, but nothing ever calls `get()` on it. The state labels are updated optimistically at call-site, so if an engine fails to start the UI shows "Running" permanently until the user manually stops.

The `_refresh_data` timer re-arms itself at the interval set when the method last ran. Changing the interval in Settings updates `self.refresh_interval` but does not cancel the old timer, so both cadences run concurrently until the old one naturally picks up the new value on its next iteration — causing a one-cycle stale-frequency artifact.

<details>
<summary>Issues (7)</summary>

1. **Shared mutable state without synchronization** — `self.recon_running`, `self.attack_running`, engine references are read/written from both daemon threads and the main thread. Add a `threading.Lock` around compound state transitions (check-then-set, stop-then-nullify).
2. **`message_queue` never consumed** — Messages are put but never processed. Either implement `_process_message_queue` on a timer (like `_process_log_queue`) or remove the dead code.
3. **No input validation on network parameters** — BSSID, target IP, and gateway IP reach engine constructors unvalidated. Add regex or `ipaddress` module checks before passing to engines.
4. **Refresh interval change doesn't reschedule timer** — `_apply_settings` updates `self.refresh_interval` but the existing `root.after` callback continues at the old cadence for one more cycle. Cancel and reschedule.
5. **UI state desyncs on engine start failure** — Buttons are disabled/enabled optimistically before the thread confirms the engine started. If the engine raises immediately, buttons stay in "running" state with no recovery path.
6. **`_clear_database` is a no-op** — Confirms with the user then logs a warning without actually clearing anything. Either implement it or disable/remove the menu item.
7. **Unbounded log widget growth** — The `ScrolledText` log accumulates indefinitely. For long-running sessions this will consume unbounded memory. Add a ring-buffer trim (e.g., delete lines beyond 10k).

</details>

<details>
<summary>Details</summary>

## Thread safety across engine lifecycle

Every `_start_*` method follows the pattern: check a boolean flag, spawn a daemon thread, optimistically update buttons. The daemon thread sets the flag to `True` inside itself, does work, then sets it back to `False` in a `finally` block. Meanwhile `_stop_*` methods read the engine reference, spawn *another* daemon thread to call `.stop()`, then immediately toggle buttons.

The race is in stop sequences. `_stop_mitm` sets `self.mitm_running = False` on the main thread, then spawns a thread that calls `.stop()` on each sub-engine and sets the reference to `None`. If the *start* method is called again before the stop-thread finishes nullifying, the new thread could see stale engine references. The buttons are re-enabled immediately in `_stop_*`, so nothing prevents a rapid stop→start cycle from overlapping.

The fix is a lock around the start/stop critical sections, or — simpler for a GUI — disabling both buttons until the stop-thread posts a completion message.

```python
# Current pattern (gui.py ~line 1360):
self.mitm_running = False  # main thread

def stop_mitm():
    # background thread
    if self.mitm_engine:
        self.mitm_engine.stop()
        self.mitm_engine = None  # ← race with next start
```

## Dead `message_queue`

`self.message_queue = queue.Queue()` is initialized in `__init__`. Every start/stop thread puts tuples like `("recon_started", None)` into it. There is no `_process_message_queue` method and no `root.after` callback that drains it. The intended design was probably to use these messages to reconcile button state after a thread completes — which would fix the UI-desync issue. Implementing the consumer is the correct path forward.

## Input validation gap

`_start_mitm` does one check: `if not target_ip`. But it doesn't validate the format. The BSSID field in `_start_attack` passes `target_bssid = self.attack_target_var.get().strip() or None` — no MAC-address validation. The timeout field in recon uses `timeout_str.isdigit()`, which rejects non-numeric input but accepts "0" as a valid timeout, which would cause an instant-return from engines that interpret `timeout=0` as "don't wait."

## Refresh interval timing

```python
def _apply_settings(self):
    new_interval = self.settings_refresh_var.get()
    if new_interval != self.refresh_interval:
        self.refresh_interval = new_interval  # stored, but old timer still ticking
```

`_refresh_data` re-arms with `self.root.after(self.refresh_interval, self._refresh_data)`. Since the old invocation is already scheduled at the previous interval, it will fire once more at the old rate, then adopt the new rate. Storing the `after` ID and calling `after_cancel` before rescheduling is the clean fix.

## Test coverage

There are no tests for the GUI module. The architecture is testable — the queue-based logging, the state machine flags, and the data-refresh methods could all be unit-tested by mocking `self.root` and `self.db`. The engine-start/stop logic could be tested by injecting mock engines. For a GUI of this complexity, at minimum the state transitions and queue processing deserve unit tests.

Not tested: thread race conditions, input validation edge cases, engine start-failure recovery, log widget memory growth under sustained use.

</details>

<details>
<summary>File map</summary>

| File | Change |
|------|--------|
| `posframework/gui.py` | New 1691-line Tkinter GUI: 6-tab interface, dark theme, threaded engine control, queue-based logging, periodic DB refresh |
| `posframework/gui_main.py` | New 15-line launcher that imports and calls `gui.main()` |
| `posframework/__main__.py` | Added `gui` subparser and dispatch; also added new attack-module CLI flags (ap-clone, krack, dos, client-isolation, printer-attacks) |

Full diff: `git diff main -- posframework/gui.py posframework/gui_main.py posframework/__main__.py`

</details>
