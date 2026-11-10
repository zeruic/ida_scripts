# Debugging with ida_scripts

Contents: [the model](#the-model), [starting](#starting), [running and waiting](#running-and-waiting), [between calls and inside one](#between-calls-and-inside-one), [breakpoints and handlers](#breakpoints-and-handlers), [looking at a suspended process](#looking-at-a-suspended-process), [modules and addresses](#modules-and-addresses), [calling into the process](#calling-into-the-process), [events](#events), [ending](#ending), [what the Windows debugger does](#what-the-windows-debugger-does), [when something is off](#when-something-is-off).

## The model

There is one debugger object, `dbg`, and one process at a time. The process is either suspended or running, and it runs only when you ask: `dbg.resume`, `dbg.run_to` and `dbg.wait` let it run and return once it is suspended again or gone, with the `Event` that ended the run. Everything else (registers, memory, the call stack, calls into the process) wants it suspended.

All of this lives in the IDA process that hosts the database. Through the IDA MCP that process stays up between `execute_python` calls, so `dbg`, the breakpoints, their handlers, the recorded events and your own variables are all still there in the next call. In a script they last for the run of the script. `REPO/tests/test_debugger_live.py` is a whole session in ten steps and makes a good worked example.

Debugging needs a database, usually of the program itself or of the library you care about. Open it first, the usual way.

## Starting

```python
event = dbg.start(r'C:\games\target.exe', args='--windowed', timeout=60)    # a 'process_start' event
event = dbg.attach(4242)                                                    # 'process_start' with info 'attached'
```

Both return with the process suspended. `start` takes `cwd` (the executable's folder by default). Leave `debugger` out for a process on this machine: the library picks IDA's local debugger for the database's file type. A failed start leaves no process behind and raises `DebuggerError` with the reason. Both wait 10 s for the process to be suspended unless you pass `timeout`, which a large program may need. Dialogs that would block a run without a user are turned off while the process starts or is attached.

Starting or attaching can move the database (see [modules and addresses](#modules-and-addresses)). IDA moves the breakpoints along, but a `Breakpoint` object, its handler and its hit count belong to the address it had. A handler given before the start is dropped without a word when the database moves: the breakpoint then simply stops the process. So look addresses up, take `Breakpoint` objects and give them handlers once the process is there, not before. The database stays moved when the process is gone, which [ending](#ending) deals with.

Breakpoints are stored in the database, so the ones saved there earlier, by the user in IDA for instance, are live in your session too, and one without a handler stops the process. Look at `Breakpoint.all()` before the first run, and disable what is not yours for the session (`bp.enabled = False`). One of those may sit where you want your own, and adding there hands you that one, still disabled, so enable what you add.

After `start` the process sits before the system's loader has run: the executable is the only module, and nothing else is mapped yet. Set breakpoints now. For code in a library that loads later, use a module-relative breakpoint (below).

## Running and waiting

```python
event = dbg.resume(timeout=120)         # run until something suspends the process
event = dbg.run_to('parse_header', timeout=30)
dbg.resume(timeout=0)                   # let it run and return None at once
event = dbg.wait(timeout=120)           # wait for a process that is already running
dbg.suspend()                           # stop a running process
```

What comes back is the event that suspended the process, with its thread selected, or the `'process_exit'` event. Without a `timeout` these wait as long as the process runs, so through the MCP always pass one. Look at `event.kind` and `event.address` before acting on it: a stop is not always the breakpoint you were waiting for. A library load does not suspend, but an exception does, and after `attach` or `suspend` the first stop can be in another thread. When you wait for one place, loop until you are there:

```python
bp = Breakpoint.add('update')
event = dbg.resume(timeout=60)
while event.kind != 'process_exit' and event.address != bp.address:
	event = dbg.resume(timeout=60)
```

When the time is up and the process is still running, the call raises `DebuggerError`. The process keeps running. That is the normal end of a trace that runs for a fixed time, not a failure, and `dbg.state` tells the two apart:

```python
try:
	event = dbg.resume(timeout=30)
except DebuggerError:
	if dbg.state != 'running':
		raise                           # a real failure
	event = None                        # still running after 30 s
dbg.suspend()
```

A stop is never lost to a timeout. If the process was suspended by the time the wait ended, the call returns that event, and `dbg.wait()` on a suspended process returns the latest event at once.

The end of such a trace is not sharp. The wait returns a little after its time, up to one more hit later, and a hit that arrives before `dbg.suspend()` has taken hold still runs its handler. The process is then suspended at that breakpoint, so the last hit in your list can be a call that has not run yet. When a count has to match a time window, or the state of the program, have the handler record `time.time()` and count the hits inside the window.

Through the MCP, keep these timeouts below the timeout of the `execute_python` call (360 s unless you pass a larger one). A long run needs no long call: the process runs on between calls (next section), so wait for a stop in slices, `dbg.wait(timeout=300)` again and again, and report what the handlers collected in between.

A call that the MCP cuts off in the middle of a wait ends in one of two ways, both seen on Windows. Either way the namespace, the breakpoints and their handlers survive, the next call is answered at once, and `dbg.state` says where things stand.

- Nothing was hitting breakpoints: the call fails with `execute timed out after … s` and the process keeps running.
- A trace was busy: the cut lands in a breakpoint's notification. The call then returns at its time limit as if the wait had ended, with a `'suspended'` event, and what it printed carries a traceback that ends in `_OperationInterrupt`. The process is suspended at that breakpoint, the hit is not counted and its handler did not run.

## Between calls and inside one

Through the MCP the debugger is served between your calls. The worker runs IDA's event loop whenever no call is using it, so a running process goes on hitting breakpoints, handlers run and can stop it, and events are recorded, all with no call of yours waiting. Two things follow:

- A trace can be left to collect. Set the handler, `dbg.resume(timeout=0)`, return, and read the list in a later call. Left alone for seven minutes, a handler ran on every hit, at the rate the program made them.
- A stop that happens meanwhile waits for you. The next call finds `dbg.state == 'suspended'`, and `dbg.wait()` returns that event at once. So a breakpoint without a handler, a handler that returns something truthy, an exception or a handler that failed (`dbg.handler_error`) can all have stopped the process since you last looked.

This was seen in the MCP's headless worker on Windows (ida-mcp 20260930, backend `idalib`). A host that runs no event loop between calls would leave the process sitting at its first event, handler or not. One check tells, on a host you have not used before: a handler that appends to a list, `dbg.resume(timeout=0)`, and the length of the list a few seconds later.

Inside a call it is the other way round. The call has the thread that serves the debugger, so the process gets past an event only while `dbg.resume`, `dbg.wait` or `dbg.run_to` is waiting. While your code computes or sleeps, the next breakpoint hit, library load or thread start holds the process where it is, and no handler runs. So after a wait that timed out, `dbg.state` is `'running'` and yet a traced program is parked at its next hit until you wait again or the call returns: what you read then is as of that hit. And `time.sleep(5)` does not let a trace run for five seconds. This does:

```python
try:
	dbg.wait(timeout=5)                 # the debugger is served for five seconds, handlers run
except DebuggerError:
	pass                                # nothing stopped the process: it is still running
```

Memory can be read and written while the process runs (`ptr('g_count').u32()`, `ptr('g_count').u32(0)`). Registers and the call stack need it suspended.

When the database is open in IDA's GUI, the user sees the same debugger and can drive it too. The breakpoints are IDA's own, and a handler still runs when the user is the one who lets the process go. A session through the GUI's own MCP connection has not been run.

## Breakpoints and handlers

```python
bp = Breakpoint.add('update')                           # by name, address, Pointer or Func
bp = Breakpoint.add(0x4de0, module='Engine.dll')        # an offset into a module, loaded or not
bp.enabled = False
bp.hits, bp.address, bp.remove()
Breakpoint.all(), Breakpoint.find('update'), Breakpoint.clear()
```

A module-relative breakpoint is named by the module's file name (any case) and an offset from its base. It is placed when the module loads, which is how to stop in a library before any of its code has run. `bp.address` is `None` until then.

A breakpoint without a handler suspends the process. A handler is called as `handler(event)` on each hit, with the process suspended and the event's thread selected, so it can read anything:

```python
sends = []
def on_send(event):
	size = dbg.reg('RDX')
	try:
		head = ptr(dbg.reg('RCX')).read(min(size, 32)).hex()
	except IDAError:
		head = None                                                     # RCX did not point at readable memory
	sends.append({ 'size' : size, 'head' : head, 'caller' : dbg.stack(2)[-1].addr })

Breakpoint.add('send_packet', handler=on_send)                          # returns None: record and run on
Breakpoint.add('alloc', handler=lambda event: dbg.reg('RCX') > 0x100000)    # truthy: stop on that condition
```

The return value decides. Falsy (a handler with no `return`, a `list.append`) lets the process run on by itself, which makes the breakpoint a trace point: thousands of hits end up in your list with no call of yours for any of them. Truthy keeps the process suspended and `dbg.resume` returns that event, which makes it a conditional breakpoint. A handler runs on the one thread that runs your calls, inside a wait or between two calls and never during your own code, so it shares your variables without locking.

A handler that raises keeps the process suspended, prints its traceback, and leaves the exception in `dbg.handler_error`. So when a trace stops early for no visible reason, look there. The usual cause is a read through a register that does not hold a valid pointer: `Pointer.read` and the typed reads raise `IDAError` on memory that cannot be read, so guard them in a handler that must keep going.

Adding a breakpoint where there already is one returns that one, and gives it the new handler when you pass one. It does not enable a breakpoint that was disabled: set `bp.enabled = True` on one you mean to use. Breakpoints can be added, disabled, enabled and removed while the process runs as well as while it is suspended, and the change takes effect at once.

Every hit is a real stop of the process, a call into Python and a resume, which is slow next to the code it interrupts. Measured on one Windows machine, on a function that ran hundreds of millions of times a second untraced: about 1 ms a hit while a call waits (some 1,000 hits a second, 700 with a handler that also reads memory and the stack), and about 0.3 ms a hit between calls (some 3,500 a second). So a function called a few hundred times a second is traced at its own pace, and one called more often is slowed to those rates. When that is too slow, have the handler return something truthy after enough hits and disable the breakpoint, or trace a caller that runs less often.

Every hit is also recorded in `dbg.events`. On a long trace, call `dbg.clear_events()` between waits, or that list grows by one `Event` for each hit.

Tracing produces a lot. Summarise before returning it (`collections.Counter`, the first and last few, a count), and write the full list to a file when the user will want it.

## Looking at a suspended process

```python
dbg.pc, dbg.sp                          # Pointers: .addr is the int
dbg.reg('RCX'), dbg.reg('RCX', 0)       # read, write
dbg.regs('RCX', 'RDX', 'R8')            # {'RCX': …, 'RDX': …, 'R8': …}. Without names: every integer register
dbg.stack(8)                            # Pointers, innermost first: where it is, then the call in each caller
dbg.threads, dbg.thread                 # assign dbg.thread to read another thread's registers
```

Addresses come back as `Pointer` from `dbg.pc`, `dbg.stack()`, `event.address` and `bp.address`, and as plain ints from `Func.start` and `Module.addr`.

A caller in `dbg.stack()` is its call instruction wherever the database has the caller's code. In any other module (a system library, say) it is where IDA guesses the call to be from the return address, which was seen to be the return address itself or a byte off. That is enough to name the function and not enough to quote the instruction. A function is known only where the database has one, so a frame in another module has no `p.func`. This names any address, by function or by module:

```python
def where(p):
	if p.func:
		return f'{p.func.name}+{hex(p.addr - p.func.start)}'
	loaded = p.module                                   # its name is the full path
	return f'{os.path.basename(loaded.name)}+{hex(p.addr - loaded.addr)}' if loaded else hex(p.addr)

[where(p) for p in dbg.stack(16)]
```

Memory is read the same way as in the database, and now comes from the process. Writes work too:

```python
state = StrucT.find('GameState').instance_at(dbg.reg('RCX'))
state['frame'], state.to_dict()
state['frame'] = 0                      # writes into the process
ptr('g_debug').u32(1)
ptr(dbg.sp).read(64), ptr(dbg.reg('RCX')).string()
```

Register names are the processor's, as IDA spells them: `RCX`, `RSP` on x64, `X0`, `SP` on arm64. Narrower ones work too, so `dbg.reg('ECX')` is an `int` argument without masking. Stopped at the first instruction of a function on Windows x64, the first four integer arguments are in `RCX`, `RDX`, `R8` and `R9`, and `ptr(dbg.sp).ptr()` is the return address.

## Modules and addresses

For the file the database was made from, IDA moves the whole database to where the process loaded it. Names and addresses from the database are then the process's own, and `func('update')` or `ptr('g_state')` need no translation.

For anything else, go through the module:

```python
engine = Module.find('Engine.dll')              # by file name or full path. None when it is not loaded
engine + 0x74e38                                # a Pointer at that offset
Module.containing(dbg.pc), ptr(dbg.pc).module   # which module an address is in
[m.to_dict() for m in dbg.modules]

engine.static_base = 0x180000000                # where another database of Engine.dll has its base
engine.to_static(dbg.pc)                        # process address -> that database's address
engine.from_static(0x180004de0)                 # and back, as a Pointer
```

`static_base` is known for the database's own file and has to be given for any other module. It is remembered per module name for the rest of the session.

## Calling into the process

```python
dbg.call('get_item', 'Item *__fastcall get_item(Inventory *inv, int slot)', inventory, 3)
func('get_item').call(inventory, 3)             # the same, with the prototype the database has
```

The process has to be suspended, and the call runs on the selected thread. Ints and strings convert by themselves. `dbg.ref(value)` passes a pointer to a copy of `value`, whose `.value` holds what the callee wrote there afterwards, and `dbg.wide(text)` passes a UTF-16 string.

The prototype is parsed before anything runs. One that does not parse, or names a type the database lacks, raises `DebuggerError` and the process is untouched. A call that fails raises `DebuggerError` too. The explicit form is the one to use when the database's prototype is missing or only guessed.

A breakpoint inside the called function fires during the call. Disable it first (`bp.enabled = False`) and enable it again afterwards. And a call runs real code in the process: it can change state or crash, and it has no time limit, so a callee that blocks leaves your call hanging with the process suspended. Call only what you understand.

## Events

Every event is recorded from the first use of `dbg`: `dbg.events` is the list, oldest first, and `dbg.event` the latest. An `Event` has `kind`, `pid`, `tid`, `address`, `module`, `code` and `info`. The kinds are `'process_start'`, `'process_exit'`, `'library_load'`, `'library_unload'`, `'breakpoint'`, `'exception'`, `'thread_start'`, `'thread_exit'`, `'suspended'` and `'other'`. Of these, `'process_start'`, `'breakpoint'`, `'exception'` and `'suspended'` leave the process suspended, and the others pass while it runs.

```python
[e.to_dict() for e in dbg.events if e.kind == 'library_load']
dbg.on('exception', lambda event: crashes.append((event.code, event.info, dbg.stack(8))))
dbg.clear_events()
```

`dbg.on(kind, handler)` calls a handler for every event of a kind. Its return value is ignored: it observes, it does not decide whether the process stops. `dbg.off(kind)` removes it. A process exit carries the exit code in `code`.

An exception event carries the code in `code` (unsigned, `0xC0000005` for an access violation on Windows) and the debugger's text in `info`. Which exceptions stop the process, and whether one is handed back to the program when it runs on, follow IDA's own exception settings for that code (`cfg/exceptions.cfg`, or Debugger options in the GUI). The library does not change them.

A program that raises exceptions as part of its normal work stops at every one of them with those settings. On Windows, a program that raised a code of its own (`RaiseException`) and caught it stopped each time with an `'exception'` event at the raise, and running on handed the exception to the program, whose handler then ran. So pass the ones you expect in a loop, inside one call:

```python
event = dbg.resume(timeout=60)
while event.kind == 'exception' and event.code == 0xE0001234:
	event = dbg.resume(timeout=60)
```

## Ending

```python
dbg.stop()          # kill the process. False when there was none, so it is safe in a finally
dbg.detach()        # let go and leave it running
bp.remove()         # for each breakpoint you added
```

End every session one way or the other, since a process left suspended under the debugger just hangs for the user. When you attached to something the user had running, `detach` is usually what they want. It has been run from a suspended process, so suspend first. `dbg.attach(pid)` in a later call takes the same process up again. In a script, do it in a `finally` inside the `with Database.open(...)` block, so the process is gone before the database closes. After either call `dbg.state` is `'none'` and `dbg.event` is a `'process_exit'` event.

Through the MCP, `close_database` ends the worker, and on Windows the program it was debugging was killed with it, suspended or running. So never close to get out of a session on a program the user wants to keep: detach first.

A session changes the database, and `close_database` saves the changes. So write a copy before the first start (`Database.current().save(path)` writes one and stays on the original) and tell the user where it is. When the database has to stay exactly as it is, close it and debug the copy instead.

Breakpoints belong to the database and outlive the process, so remove the ones you added. `Breakpoint.clear()` removes every breakpoint, the user's own included.

And the database stays where the process was loaded. IDA does not move it back when the process is gone, so every address in it is now the one that process had, which is not where the user left their database. Note the base before the first start and move the database back after the last stop:

```python
import ida_nalt, ida_segment
base = ida_nalt.get_imagebase()         # before dbg.start or dbg.attach
...
dbg.stop()
moved = ida_segment.rebase_program(base - ida_nalt.get_imagebase(), ida_segment.MSF_FIXONCE)    # 0 when it worked
Database.current().wait()               # the move queues analysis: let it finish before you look or save
```

Names, pseudocode and the remaining breakpoints follow the move. `Breakpoint` objects and `Pointer`s from before it do not, so look them up again.

This puts the addresses back, not every detail. After one session on a small program, a database moved back this way had one function more than before (IDA's analysis after a move had turned two data bytes into code) and eight items that showed a number differently. Nothing a reader would notice, but not the same file either, which is what the copy is for.

## What the Windows debugger does

Seen with IDA 9.4's win32 debugger on an x64 program: from a script through idalib, once inside `idat`, and as sessions spread over many calls of the IDA MCP. Other debuggers may differ in these very points.

- `dbg.start` suspends before the loader runs: the start event has no address, and the executable is the only module.
- IDA moves the database to the address the process is loaded at, and leaves it there when the process is gone.
- A module-relative breakpoint is placed for a file name, or for the full path exactly as the debugger reports it. A path spelled another way is matched when the module loads.
- The callers in IDA's stack trace are guessed from return addresses. With the innermost function at its first instruction every caller came back as its return address, and once as a byte inside the instruction before the call. `dbg.stack()` corrects both where the database has the caller's code.
- `dbg.suspend` reports in the thread that was running and leaves no extra event behind. `dbg.attach` comes in a thread of its own, which exits when the process runs on, so the first event after an attach may be that thread's.
- No load events come for the libraries a process already had when you attached. `dbg.modules` has them all the same.
- Two breakpoints at one address, an absolute and a module-relative one, give two events for one hit. Use one.
- Paths with spaces are fine.

`REPO/tests/README.md` has the full list, with what was verified where. The Linux and macOS debuggers have not been run. macOS refuses to let IDA debug without elevated permissions: `dbg.start` raises with IDA's message. Report that to the user and stop there.

## When something is off

- `DebuggerError: … no process is being debugged`: the process exited or was never started. `dbg.event` says how it ended.
- `DebuggerError: … the process is running, suspend it first`: an earlier wait timed out. `dbg.suspend()`, or `dbg.wait(timeout=…)` for the stop you were expecting.
- A breakpoint never hits: check `bp.address` (still `None` means its module has not loaded, so check the name against `dbg.modules`), `bp.enabled`, and that the code runs at all.
- A trace stopped although its handler returns nothing: `dbg.handler_error`.
- Registers look wrong: they belong to `dbg.thread`, the thread of the latest stop. `event.tid` and `dbg.threads` tell which one that is.
- Behaviour that contradicts this page: say so in your report, with the smallest script that shows it. The debugger has only been run against Windows so far, and the library's own tests are where a fix belongs.
