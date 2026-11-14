# ida_scripts
This is a collection of IDA Python scripts, which hope to make IDAPython much more user-friendly and enjoyable :D.

It works on **IDA 9.x** (tested on 9.4), with or without a debugger: inside IDA, in a headless script through idalib, or driven by an AI agent through an IDA MCP server.

## Features
This is just an overview, please check the documentations below for the full set of features.
- `memory`
	- `Pointer` (shorthand `ptr`), from an address or a symbol name
		- RW `bytes, int, float, pointer, string, wide string, array`
		- Reads the debugged process when there is one, the database otherwise
		- Name, comment, segment, containing function and module
		- Cross references to and from, as `Xref`
		- Hex dump
		- Arithmetics ( + - == < ), hashable
	- `Insn` and `disasm(start, end)`
- `func`
	- `Func` (shorthand `func`)
		- Find by name, address, or regex over all names
		- Rename, comment, C prototype
		- Callers, callees, and every call it makes (direct, tail or indirect)
		- An outline: its calls in order, each with the callee's comment, and the strings it uses
		- A list of callee names to ignore, kept in the database, for the runtime helpers that drown every list
		- Strings and data it refers to, instructions, chunks
		- Thunks and where they jump, also the single jumps IDA does not mark
		- Fingerprint, to find the same function in another build
		- Decompile to yield `CFunc`
	- `CFunc`
		- Get pseudocode, cut to a length or to a window, with long identifiers shortened, with or without the local declarations
		- Leave out the statements that only call an ignored function, or the lines a pattern matches, together with the `if` they would leave empty
		- Every call with its arguments
		- `grep` inside it, save it to a file
	- `grep` over the pseudocode of many functions, `show_code` to print several functions
		- Get body represented as a networkx.DiGraph (really just a tree)
			- Each node is a `CItem`
	- `CItem`
		- Property accessors
			- Customised convenient accessors such as
				- Getting the struct / member being accessed
				- Getting the number
		- DFS search for node with lambda condition
		- Subtree query for more complex searches
- `struc`
	- Types (the type defs, not instances)
		- `StrucT`
			- Find by name
			- Declare from C text or a header file
			- Get `id, name, members, size, declaration`
			- Subscript access for member `MemberT`
			- Get `StrucI` instance from `Pointer`
			- Create struct
			- Add & delete member
			- Add member, automatically managing gaps
		- `MemberT`
			- Get `id, name, type, offset, size`
	- Instance (instances with memory addresses)
		- `StrucI`
			- Get `members`
			- Subscript access for member value, read and write
	- Apply C prototypes to many functions
- `debugger`
	- `dbg`
		- Start, attach, resume, run to, suspend, stop
		- Every call waits until the process is suspended again and returns the `Event`
		- Registers, program counter, stack pointer, call stack
		- Call a function in the process
		- Events recorded as they happen, handlers per kind of event
	- `Breakpoint`
		- By address, by name, or by offset into a module that has not loaded yet
		- A handler per breakpoint, which can log and let the process run on
- `module`
	- `Module`
		- Enumerate all modules
		- Find module by name, or by an address inside it
		- Translate addresses between the process and the database
- `misc`
	- Search names, comments and strings by regex
	- `show` prints any list of the library's objects, a line for each
	- Name and comment many addresses at once
	- Export every annotation of a database, import it into another copy
- `session`
	- `Database`
		- Open, save a snapshot, close, also as a context manager
- All classes are pretty-printed when evaluated, and turn into JSON with `to_dict()`, or with `jsonable()` for any nesting of them!

## Usage
In IDA Pro, select `File > Script File` and choose the `load.py` script. Run it again to reload the scripts after changing them.

Anywhere else that has IDA's Python (idalib, or the Python of an IDA MCP server), put this folder on `sys.path` and import everything:

```python
from ida_scripts import *

with Database.open('target.i64'):
	f = func('main')
	print(f.outline())
	print(f.pseudocode(max_lines=40))
	show(f.callers, f.decompile().calls)
	for found in Func.search(r'^Player::'):
		print(found, found.strings)
```

While debugging:

```python
dbg.start('target.exe')                    # suspended at the process start
Breakpoint.add('update')
event = dbg.resume()                       # suspended at update, its thread selected
print(dbg.regs('RCX', 'RDX'), dbg.stack())
state = StrucT.find('GameState').instance_at(dbg.reg('RCX'))
print(state['frame'], state.to_dict())

seen = []
Breakpoint.add(0x4de0, module='Engine.dll', handler=lambda event: seen.append(dbg.reg('RCX')))
Breakpoint.add('shutdown')
dbg.resume()                               # the handler returns None, so the process runs on to shutdown
engine = Module.find('Engine.dll')
print(len(seen), ptr(engine + 0x74e38).u32())
dbg.stop()
```

## Skill
`skills/ida-scripts` is a skill for AI agents that work with IDA: how to use this library, and where its state lives between an agent's calls. It works with the [IDA MCP server](https://github.com/HexRaysSA/ida-mcp), which keeps one IDA process per database, so a debugging session carries on from one call to the next.

In Claude Code, install it together with this library:

```
claude plugin install ida-scripts --marketplace Zerui18/ida_scripts
```

To use a clone of this repository instead, install from its folder. Claude Code then reads the plugin from the clone in place, on Windows too (`C:\path\to\ida_scripts`):

```
claude plugin install ida-scripts --marketplace /path/to/ida_scripts
```

On macOS and Linux, linking only the skill into your skills folder works as well:

```
ln -s /path/to/ida_scripts/skills/ida-scripts ~/.claude/skills/ida-scripts
```

`skills/ida-scripts/references/api.md` is generated from the code. After changing the API, `python skills/ida-scripts/scripts/api_reference.py` writes it again, and the tests fail until it is current.

## Documentation
[Documentation](https://zerui18.github.io/ida_scripts/ida_scripts.html) is auto-generated by pdoc:

```
IDA_SCRIPTS_NO_IDA=1 pdoc ida_scripts '!ida_scripts.utils' '!ida_scripts.compat' -d numpy --no-show-source -o docs
```

## Tests
`python tests/run.py` runs everything against small fixture programs, see [tests/README.md](tests/README.md).
