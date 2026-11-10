# Handoff: continuing on Windows

This note is for whoever picks the `ida9` branch up next, most likely a fresh AI session on the owner's Windows machine. Delete it before the branch is merged.

## Where things stand

The library was reworked for IDA 9.x on macOS. Everything is committed on `ida9`. The whole suite passes on IDA 9.4 there (13 test files, 287 tests), with one skip: the live debugger test, because macOS would not let IDA debug.

So the one thing nobody has seen work is **`debugger.py` and `module.py` against a real process**. They were written from IDA 9.4's stubs and tested against a fake of `ida_dbg` and `ida_idd` (`tests/fakes`). Running them for real is the job on Windows.

## First steps

1. Find the Python that has idalib and the version IDA is set up for. `tests/run.py` looks at `IDA_PYTHON`, then `%APPDATA%\Hex-Rays\IDA Pro\venv\Scripts\python.exe`, then the Python running it.
2. `python tests\run.py`. The static tests use the arm64 Mach-O programs in `tests/fixtures/bin`, so they need no compiler, only the ARM64 decompiler. This is also the first run of the runner's Windows code (`msvcrt` locking, path handling), so a failure here may be the runner's, not the library's.
3. `python tests\run.py debugger_live`, from a Developer Command Prompt so that `cl` is on `PATH` (`clang` or `gcc` work too). It builds `tests/fixtures/live/debug_target.c`, opens a database of it and debugs it in nine steps.
4. Read `tests/README.md`. Its last section lists what only the live run can tell, most likely problems first.

## When a live step fails

- Find out what IDA really does, with a small script against the real debugger, before changing anything. Do not guess.
- Fix `ida_scripts/debugger.py` or `module.py`.
- Then make the fake behave like the real thing (`tests/fakes/process.py`), and add or change a test in `tests/test_debugger.py`, so the behaviour stays covered on machines that cannot debug.
- `tests/test_debugger.py` has a conformance test that compares every name and parameter list of the fake with the real `ida_dbg` and `ida_idd`. Keep it passing.
- Windows suspends a process by breaking in a new thread, which can leave an extra event. The live test allows for it in step 7. Step 8 (`run_to`) may need the same.

## Rules the code follows

- **IDA 9.x only**, tested on 9.4. 9.4 deprecates the `func_t` and `segment_t` API (`ida_funcs.get_func`, `ida_segment.getseg`, `ida_hexrays.decompile_func`) and even `idautils.Functions`, `FuncItems` and `Chunks`. The package uses none of them. `tests/test_api_names.py` fails on any IDAPython name that does not exist or is deprecated.
- **Never guess an IDAPython name.** Look it up in the installed stubs, the `python` folder of the IDA installation, signatures and docstrings included.
- **Version-sensitive calls live in `ida_scripts/compat.py`**, with the pre-9.4 spelling as an untested fallback where it is one line.
- **`Func` holds only its start address.** `func` is the module, and the module is callable: `func('main')` is `Func('main')`. Do not add a function named `func`.
- **Anything that means an address** takes an int, a symbol name, a `Pointer` or a `Func`, through `utils.to_ea`.
- **Errors** are `IDAError`, `DecompileError` and `DebuggerError`, with a message that says what was attempted.
- **`to_dict()`** comes from `auto_repr` and must survive `json.dumps`.
- **Bulk changes refresh the decompiler once**, at the end (`memory.set_name`, `func.set_prototype`, then `compat.refresh_decompiler()`).
- **Modules import without IDA** (`IDA_SCRIPTS_NO_IDA=1`), which the docs need: IDA modules are imported under `if IN_IDA:`.
- **`load.py` calls `_unload()`** on a module that defines it before reloading. The debugger uses that to remove its hooks, which must never stack.

## The owner's style

- Tabs. Single quotes. `from typing import *`.
- Docstrings as `''' text '''`, a one-line summary first, numpy sections (`Parameters`, `Returns`) where the parameters need explaining. Everything public has one: the docs are generated with pdoc, and `tests/test_outside_ida.py` checks it.
- Few comments. A banner for a group of methods (`# READ/WRITE`) is fine. A comment only where the reason is not obvious.
- `@auto_repr` for representations, static factories on the class (`Func.find`), read/write dual methods (`value is None` reads).
- Old names stay as aliases (`Func.func_at`, `CFunc.psuedocode`, `StrucT.add_struc`).
- Commits: a sequence of small ones, each `scope: summary` on one line.

## Things that cost time to find

- idalib crashes when `DeprecationWarning` is an error while it starts. Never use `-W error`. The harness sets the filter after the database is open.
- Starting idalib drops the caller's entries at the front of `sys.path`. `compat` puts them back.
- `ida_bytes.get_bytes` returns `0xFF` bytes for unmapped addresses. `Pointer.read` uses `get_bytes_and_mask`.
- About once a minute, idalib opened a database without its root information (no input file name, image base 0) on the Mac, probably because of an IDA MCP server's periodic check. `Database.open` opens it again when that happens. If something similar shows up on Windows, look there first.
- IDA 9 keeps the holes of a struct as real `_BYTE gapXX[n]` members and reuses the id of a deleted member.
- `ida_dbg.enable_bpt` on a location reports failure even when it worked. Adding the same breakpoint twice reports success and adds nothing.

## Not done

- The live debugger run, and whatever it turns up.
- x86 and x64 code, PE and ELF files, IDA 9.0 to 9.3, Linux.
- `docs/` is generated from the code as it was on macOS. Regenerate it after changes (the command is in `README.md`).
