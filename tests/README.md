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
| `memory`, `func`, `misc`, `struc`, `session`, `load.py` | IDA 9.4 on macOS, arm64 Mach-O fixtures, database only |
| Reads and writes of a debugged process (`Pointer`, `StrucI`) | A fake process |
| `debugger`, `module` | A fake of `ida_dbg` and `ida_idd`, kept in step with the real 9.4 names and signatures by a test |
| `debugger`, `module` on a real process | **Nothing yet.** macOS refuses to let IDA debug without elevated permissions, so `test_debugger_live.py` skips there with IDA's message |
| x86 and x64 code, PE and ELF files, IDA 9.0 to 9.3, Windows and Linux hosts | Nothing yet |
| The decompiler tree (`CFunc.body`, `CItem`) | `networkx` 3.7, and the small stand-in the tests fall back to. Also end to end: an access into a struct's gap, found in the tree, becomes a member |

## The live debugger test

`python tests/run.py debugger_live` builds `tests/fixtures/live/debug_target.c` with the first C compiler on `PATH` (`cl`, `clang` or `gcc` on Windows), opens a database of it, and debugs it in nine steps: start, a breakpoint by name, registers and the call stack, memory, a call into the process, a module-relative breakpoint, handlers, `run_to` and `stop`. Each step says what it attempted when it fails, and the steps after a failed one are skipped.

On Windows, `cl` is on `PATH` only in a Developer Command Prompt.

The first run on a machine where debugging is allowed is the first real run of the debugger module. These are the things only that run can tell, most likely first:

1. Whether `dbg.start` leaves the process suspended at its start (it asks IDA for a breakpoint at the process start), and whether the hooks see the start event before the wait returns.
2. Whether IDA moves the database to the address the process is loaded at. Step 4 compares the database's address of `counter` with the address the target reports.
3. How IDA matches the module name of a module-relative breakpoint. The module records such a breakpoint under the name given, and gives it the module's full path when that module loads.
4. Whether a handler can let the process run on from inside the breakpoint notification, both during `dbg.resume` and when the process was resumed from IDA itself.
5. `dbg.call` (IDA's Appcall), `dbg.stack`, `dbg.regs()` without names, `dbg.suspend` on a running process, `dbg.detach` and `dbg.attach`.
6. How a suspended process reports itself. Windows suspends by breaking in a new thread, which can leave one extra event for the next `resume`. Step 7 allows for that, step 8 may need the same.
7. Paths that contain spaces, and module paths in another form than given (case, short names). Matching falls back to the file name.
