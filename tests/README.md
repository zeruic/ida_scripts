# Tests

`python tests/run.py` runs every `tests/test_*.py`, each in its own process. `python tests/run.py memory struc` runs the files whose name contains one of the words.

## What it needs

- **IDA 9.x with idalib**, and a Python that can `import idapro`. The runner uses `IDA_PYTHON` when it is set. Otherwise it looks for the virtual environment in IDA's user folder (`~/.idapro/venv` on macOS and Linux, `%APPDATA%\Hex-Rays\IDA Pro\venv` on Windows), and then tries the Python that runs it. That Python has to be the version IDA is set up for (`idapyswitch`).
- **The ARM64 decompiler.** The fixtures are small arm64 Mach-O programs, on every system.
- **`networkx` is optional.** `CFunc.body` needs it (`pip install networkx` into IDA's Python). The tree tests run on it when it is installed, and on a small stand-in in `tests/fakes` either way.
- **No compiler, except on macOS and for the live debugger test.** macOS compiles the fixtures from `tests/fixtures/*.c` with clang. Other systems use the copies in `tests/fixtures/bin`. After changing a fixture, run `python tests/run.py --prebuild` on macOS and commit the new copies.

About once a minute, for a second or so, idalib opened a database without its root information here (no input file name, image base 0), with an IDA MCP server running on the machine. `Database.open` notices and opens it again.

Never run Python with `-W error`: idalib crashes when `DeprecationWarning` is an error while it starts. The harness turns it into an error once the database is open, which is how a deprecated IDA call fails a test.

## How a test gets its database

`tests/harness.py` gives each test process its own temporary copy of a fixture's analysed database, so files run side by side and may change it. A test class sets `fixture` to pick one (default `sample`), and `fresh = True` when it changes the database, so the next class starts from an unchanged copy. `harness.sym('compute')` is the address of a fixture symbol.

Two tests look at the package as a whole. `test_api_names.py` fails when the package uses an IDAPython name that does not exist in the running IDA or is deprecated there. `test_outside_ida.py` checks that the package imports without IDA and that everything public has a docstring.

## What has been verified, and where

| Area | Verified against |
|---|---|
| `memory`, `func`, `misc`, `struc`, `session`, `load.py` | IDA 9.4 on macOS and on Windows, arm64 Mach-O fixtures, database only |
| Reads and writes of a debugged process (`Pointer`, `StrucI`) | A fake process. `Pointer` also on a real one, in the live test |
| `debugger`, `module` | A fake of `ida_dbg` and `ida_idd`, kept in step with the real 9.4 names and signatures by a test, and behaving the way the win32 debugger was seen to |
| `debugger`, `module` on a real process | IDA 9.4 on Windows 11: the win32 debugger on an x64 program built with MSVC, through idalib (`test_debugger_live.py`), and once by hand inside IDA (`idat`). macOS refuses to let IDA debug without elevated permissions, so the test skips there with IDA's message |
| The Linux and macOS debuggers, x86 code, ELF files, IDA 9.0 to 9.3 | Nothing yet. Of x64 PE files, only what the live test touches |
| The decompiler tree (`CFunc.body`, `CItem`) | `networkx` 3.7, and the small stand-in the tests fall back to. Also end to end: an access into a struct's gap, found in the tree, becomes a member |

## The live debugger test

`python tests/run.py debugger_live` builds `tests/fixtures/live/debug_target.c` with the first C compiler on `PATH` (`cl`, `clang` or `gcc` on Windows), opens a database of it, and debugs it in ten steps: start, a breakpoint by name, registers and the call stack, memory, a call into the process, a module-relative breakpoint, handlers, `run_to`, detach and attach, and `stop`. Each step says what it attempted when it fails, and the steps after a failed one are skipped.

On Windows, `cl` is on `PATH` only in a Developer Command Prompt (or after `vcvars64.bat`).

## What the win32 debugger does

Seen with small scripts against IDA 9.4's own `ida_dbg` while the live test was first made to pass. The fake in `tests/fakes` does the same, so the tests that run everywhere cover it. A first run with another debugger (Linux, macOS) should check these first.

1. `dbg_suspend_process` comes behind the notification of every event that suspends the process: `dbg_bpt`, `dbg_run_to`, `dbg_process_start`, `dbg_process_attach`, `dbg_exception` and the step notifications. `ida_dbg.get_debug_event()` still describes that event. It does not come when a hook continued the process from inside the notification. Alone, with a `PROCESS_SUSPENDED` event, it is `suspend_process` taking effect. The module records one event either way.
2. `dbg.start` leaves the process suspended before the system's loader has run. The start event has no address, and the executable is the only module until the process runs on.
3. IDA moves the database to the address the process is loaded at.
4. IDA places a module-relative breakpoint when its path is the module's full path as the debugger reports it, or just a file name, in any case. It does not place one whose path is spelled another way (a short `PROGRA~1` name, say): the module gives that one the reported path when the module loads.
5. A handler can let the process run on from inside the breakpoint notification (`request_continue_process`, then `run_requests`), during `dbg.resume` and when something else runs the process.
6. A suspended process reports itself in the thread that was running, and leaves no extra event for the next `resume`. An attach does come in a thread of its own, which exits when the process runs on. No load events come for the libraries the process already had.
7. The exception notification has the code as a signed int (`0xC0000005` as `-1073741819`), the detach notification has no process id, and `attach_process` returns -1 for a process id that does not exist.
8. `enable_bpt` with a location returns `True` (on macOS it returned `False` and did it all the same).
9. Two breakpoints at one address, an absolute and a module-relative one, make IDA send `dbg_bpt` twice for one hit. The module records two events then. Nothing guards against it.
10. Paths with spaces are fine.
