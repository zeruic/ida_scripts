---
name: ida-scripts
description: Use ida_scripts, a Python library for IDA Pro 9.x, to reverse engineer and debug binaries with short calls instead of raw IDAPython. Covers functions and pseudocode (search, callers, callees, strings, grep), memory and struct reads, bulk renames and comments, moving names and annotations between databases or builds, and a debugger with breakpoint handlers, registers, call stacks and calls into the process. Use this skill whenever the task involves IDA Pro, an .i64 or .idb database, the IDA MCP (open_database, execute_python), idalib, decompiling or disassembling a binary, renaming or annotating functions, declaring structs, or debugging, tracing or setting breakpoints in a process, even when the user does not mention ida_scripts. Read it before writing any IDAPython or ida-domain code and before starting a debugging session, because it says where state lives between calls.
---

# ida_scripts

`ida_scripts` is a Python library over IDAPython for IDA 9.x. It turns the daily moves of reverse engineering into short calls (`func('update').pseudocode(max_lines=40)`, `f.callers`, `StrucT.find('Player').instance_at(addr).to_dict()`, `Breakpoint.add(..., handler=...)`), and it already steps around the traps of IDA 9.4, where much of the older API is deprecated or gone. Reach for it first, and drop to raw IDAPython only for what it does not cover.

The library is the repository this skill ships in. `${CLAUDE_SKILL_DIR}` is the folder this file is in (when you see that placeholder unfilled, put the folder's path in its place), and the repository is two folders above it: that folder holds the `ida_scripts` package. It is called REPO below.

## Where the code runs, and where the state lives

Nothing here keeps state in the conversation. The open database, its unsaved edits, your variables, the debugged process, its breakpoints and their handlers all live inside one IDA process. So choose the host by how long that process has to live.

| Host | The process lives | Use it for |
|---|---|---|
| The IDA MCP's `execute_python` | From `open_database` until `close_database` | Interactive work, and every debugging session |
| A script run with IDA's Python (idalib) | For one run of the script | Batch jobs, and anything that should be repeatable |
| IDA's GUI, `File > Script file` on `REPO/load.py` | As long as IDA is open | When the user works in IDA themself |

### Through the IDA MCP

Run this once after `open_database`:

```python
import os, sys
repo = os.path.dirname(os.path.dirname(os.path.realpath(r'${CLAUDE_SKILL_DIR}')))    # through a link first, then up
assert os.path.isdir(os.path.join(repo, 'ida_scripts')), f'{repo} is not the ida_scripts repository'
if repo not in sys.path:
	sys.path.insert(0, repo)
from ida_scripts import *
jsonable(Database.current())
```

From then on every `execute_python` call on that database runs in the same namespace, on IDA's main thread. This is what makes stateful work possible, so use it:

- Keep handles in variables (`f = func('update')`, `player = ...`) and reuse them in later calls. Imports, variables, `dbg`, breakpoints and handlers all stay until `close_database`.
- The value of the last expression comes back, and it has to be JSON. Library objects are not, so wrap what you return in `jsonable(...)`, which takes any nesting of objects, lists and dicts. `print(...)` works as well and shows each object's short form.
- A call that raises, or that runs into its timeout (360 s unless you pass `timeout`), is cut off where it stands. The namespace survives, with whatever the call had assigned before that point.
- The MCP's own `db` (an ida-domain database) and its `reference` tool are still there and mix freely with the library. Do not reuse the name `db`.
- `close_database` saves the database and ends the process. Opening it again gives an empty namespace, so run the lines above again. That is also how to pick up an edit to the library itself: `load.py` cannot run inside an MCP worker.
- Each database has its own process. Two open databases are two namespaces (pass `instance_id`), and data moves between them as JSON, through your reply or a file.

### In a script

```python
import sys
sys.path.insert(0, REPO)
from ida_scripts import *

with Database.open('/path/to/target.i64') as db:    # a binary works too, with analyze=True
	...
	db.save()                                       # leaving the block closes without saving
```

Run it with the Python that has idalib: `~/.idapro/venv/bin/python3`, on Windows `%APPDATA%\Hex-Rays\IDA Pro\venv\Scripts\python.exe`. Never pass `-W error`, which crashes idalib while it starts. A process hosts one database at a time, and a database that is open in IDA's GUI cannot be opened by a script at the same moment.

## What holds everywhere

- **Anything that means an address** can be an `int`, a `'0x…'` string, a symbol name, a `Pointer` or a `Func`. So `func('update')`, `ptr('g_config')` and `Breakpoint.add('update')` all work without a lookup first.
- **Addresses come back as `Pointer`** wherever one is handed to you (`ptr(...)`, `dbg.pc`, `event.address`, `StringRef.address`, an `Xref`'s `frm` and `to`). `.addr` is the `int`, `p + 8` is another `Pointer`, and a `Pointer` equals another `Pointer` or an `int` with the same address. `Func.start`, `Call.site` and `Module.addr` are plain ints. `references/api.md` gives the type of every property.
- **Names are IDA's names.** A C symbol in a Mach-O file has a leading underscore (`_main`), a C++ one is mangled. A name the database lacks raises `LookupError`. When unsure of the spelling, search: `Func.search(r'main$')`, `search_names(r'config')`. `Func.find(name)` returns `None` instead of raising.
- **Reads follow the debugger.** `Pointer` and struct reads come from the debugged process while there is one and from the database otherwise, so the same line works in both. Writes go to the process only.
- **Errors say what was attempted.** They are `IDAError`, with `DecompileError` and `DebuggerError` as its kinds.
- **Ask the library.** `help(Func.search)` in the session prints the full docstring, and what a call prints comes back with its result. `references/api.md` lists every public name with its signature and one line, and is the place to look before guessing a method.
- **Keep the output small.** Pseudocode and whole-database listings are how a session drowns. Cap them (`max_lines`, `limit`, a slice), grep instead of dumping, and write anything large to a file (`CFunc.save(path)`, `json.dump`) that you then search.

## Reading a binary

```python
f = func('update')                                    # by name or address. Func.at(ea): the function containing ea
f.name, f.prototype, f.comment                        # read them, or assign to change them
Func.search(r'^Player::', limit=50)                   # regex over every name
print(f.pseudocode(decls=False, max_lines=60, shorten=40))
print(f.decompile().grep(r'hp|health', context=1))    # like grep -n over the pseudocode
[c.name for c in f.callers], [c.name for c in f.callees]
[(c.kind, c.text, c.site) for c in f.calls]           # each call f makes, in order: 'direct', 'tail' or 'indirect'. c.target is the Func
[(x.func, x.kind) for x in f.xrefs_to]                # each use of f: 'call', 'jump' (a tail call) or 'offset' (its address is taken)
f.strings                                             # [(address, text)] the function refers to
[(s.address, s.text, [g.name for g in s.funcs]) for s in strings(r'(?i)password')]
ptr('g_count').u32(), ptr('g_name').ptr().string(), ptr('g_table').array('i', 4)
ptr('g_count').xrefs_to()                             # Xref: frm, to, kind ('call', 'read', 'write', …), func
[i.text for i in ptr(0x401000).disasm(8)]
```

IDA 9.4 prints argument names inside calls, as in `compute(a1: argc)`. That is the decompiler's hint style, not part of the code.

Structs are declared from C text and then read at any address:

```python
StrucT.parse('struct Vec2 { float x; float y; }; struct Player { int id; const char *title; struct Vec2 pos; struct Player *next; };')
player = StrucT.find('Player').instance_at('g_player')
player['id'], player.to_dict()                        # one value, or all of them, nested structs included
ptr(player['title']).string()                         # a pointer member is an address: follow it yourself
after = StrucT.find('Player').instance_at(player['next'])
StrucT.find('Player').add_member_auto('int hp', 0x40) # takes its room out of a gap, the rest stays in place
```

## Changing a database

Rename, comment and type in bulk. Each of these refreshes the decompiler once at the end, where `f.name = …` in a loop refreshes every time:

```python
rename_all({0x401000: 'parse_header', 'sub_401200': 'read_chunk'})
comment_all({'parse_header': 'validates the magic, then reads the chunk table'})
annotate_all({0x401400: ('free_chunk', 'the caller owns the buffer')})        # {address: (name, comment)}
apply_prototypes({'parse_header': 'int __fastcall parse_header(Header *h, int size)'})
```

Each returns how many entries it changed. Two quiet outcomes are worth a check afterwards. `rename_all` uses a numbered variant (`name_0`) when a name is taken, which `Func.find(name)` or `find_symbol(name)` shows. `apply_prototypes` skips a prototype IDA refuses, and the count is short then.

Edits stay in memory until the database is saved: `save_database` through the MCP, `db.save()` in a script. `Database.current().save('/path/snapshot.i64')` writes a copy and keeps working on the original, a cheap checkpoint before a large change, since closing through the MCP saves whatever is there.

Work moves between copies of a binary, and between builds of a program, as JSON:

```python
data = export_annotations()             # names, comments, prototypes and types that people or scripts added
import_annotations(data)                # in another copy of the same binary

prints = export_fingerprints()          # {fingerprint: name}, in the build that has the names
rename_all(match_functions(prints))     # in the other build: only functions whose code matches exactly one
```

A fingerprint is a hash of the function's mnemonics, in order. It ignores operands, so two functions that differ only in a constant, a global or a call target share one, as every small getter of the same shape does. Both steps leave out what is not unique: `export_fingerprints` drops a fingerprint that several functions of its build have, and `match_functions` drops one that several functions of the other build have. So a match is strong for a function of some size and weak for a tiny one, where the callers and callees that already matched are the evidence to check. `f.fingerprint` on both sides tells why a function was left out. When you name something on evidence other than a unique match, say so in your report.

## Debugging

There is one debugger, `dbg`, and it lives in the same process as everything else. Through the MCP a session therefore spans as many calls as you like: start the process in one call, look around in the next. Read `references/debugging.md` before the first session. The shape of it:

```python
dbg.start(r'C:\games\target.exe')                     # suspended at the process start
seen = []
Breakpoint.add('update')                              # no handler: the process stops here
Breakpoint.add(0x4de0, module='Engine.dll',           # Engine.dll may load later
	handler=lambda event: seen.append(dbg.regs('RCX', 'RDX')))    # returns None: log and run on
event = dbg.resume(timeout=120)                       # runs until something stops it
jsonable({'event': event, 'pc': dbg.pc, 'stack': dbg.stack(8), 'seen': len(seen)})
```

Four things carry most of the weight:

- **Run the process with a call that waits**: `dbg.resume`, `dbg.wait`, `dbg.run_to`. Each returns the `Event` that suspended the process. Give each a `timeout` shorter than the `execute_python` call's own. When nothing stopped the process in that time, the call raises a `DebuggerError` you can catch and the process keeps running, which beats a call cut off in the middle of its wait. `dbg.wait(timeout=…)` in a later call picks it up again, and `dbg.suspend()` stops it.
- **A handler decides whether its breakpoint stops.** It is called as `handler(event)` with the process suspended. Returning something falsy lets the process run on, which is how to trace thousands of hits into a list without a round trip for each. Returning something truthy stops there. An exception in a handler stops too, and is kept in `dbg.handler_error`.
- **Check `dbg.state` instead of assuming it** (`'none'`, `'running'`, `'suspended'`) at the start of a call that depends on it. The process may have exited, and registers, `dbg.pc` and `dbg.stack()` need it suspended.
- **Starting or attaching takes hold of a real program on the user's machine.** Do it for the target they asked about, and end the session on purpose: `dbg.stop()` kills the process, `dbg.detach()` lets it live.

The debugger has run for real on Windows (IDA 9.4, the win32 debugger, x64). macOS refuses to let IDA debug without elevated permissions: `dbg.start` then raises with IDA's message, which is to be reported, not worked around.

## When the library does not cover it

Raw IDAPython runs in the same namespace (`import ida_bytes`), and the library's objects hand you what it needs: `f.start`, `ptr.addr`, `StrucT.tif`, `Breakpoint.bpt()`. Two cautions for IDA 9.4. The `func_t` and `segment_t` API is deprecated (`ida_funcs.get_func`, `ida_segment.getseg`, `ida_hexrays.decompile_func`, even `idautils.Functions`), and `ida_struct` and `ida_enum` are gone. `ida_scripts.compat` (`from ida_scripts import compat`) has spellings that work across 9.x (`compat.func_start(ea)`, `compat.func_chunks(start)`, `compat.segment_name(ea)`, `compat.decompile(start)`). And never guess an IDAPython name: look it up in the stubs of the installation (`python/ida_*.py` in IDA's folder) or with the MCP's `reference` tool.

When you needed something twice that the library lacks, say so in your report. The library grows from exactly such findings.

## Reference files

- `references/api.md` Every public class, method and function with its signature and a one-line description. Search it before guessing a name.
- `references/debugging.md` A debugging session from start to end: waiting and timeouts, tracing with handlers, modules and address translation, calls into the process, events, and what the Windows debugger was seen to do.
