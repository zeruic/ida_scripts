# Handoff: testing the skill on Windows

This note is for the session on the owner's Windows machine, the one that made the live debugger run pass. Delete it before the branch is merged.

## Where things stand

The `skill` branch adds a skill for AI agents that use this library. It was written and tried on macOS, where IDA cannot debug. So everything it says about the database is checked, and everything it says about a debugging session through the IDA MCP is reasoned from the code and from your notes in `tests/README.md`. Checking that part against a real process is the job here.

What the branch adds:

- `skills/ida-scripts/SKILL.md`: where state lives, the three ways to run code, recipes for reading and changing a database, the core of debugging.
- `skills/ida-scripts/references/debugging.md`: a whole debugging session, loaded only when one starts.
- `skills/ida-scripts/references/api.md`: every public name with its signature, written by `skills/ida-scripts/scripts/api_reference.py`. Never edit it by hand.
- `tests/test_outside_skill.py`: fails when `api.md` is stale, or when an example in the skill calls a name or passes an argument that does not exist.
- `.claude-plugin/`: manifests, so the repository installs as a Claude Code plugin that carries the skill and the library together.
- Two small library changes: `jsonable` is exported from the package, and `Pointer.addr` has a docstring.

## The decision behind it

The owner asked whether a skill or a new MCP server fits better, since the debugger is stateful. The answer was a skill on top of the Hex-Rays IDA MCP (`open_database`, `execute_python`, `close_database`), and no new server. The state lives in an IDA process, and that MCP already keeps one process and one Python namespace per database between calls. A breakpoint handler is a Python function inside that process, so a trace of thousands of hits needs no round trip. A server with one tool per action would lose that.

The whole decision rests on one claim nobody has seen work: **a debugging session that spans several `execute_python` calls on a real process.** If it does not hold on Windows, say so plainly and early. That changes the design, not a sentence.

## What was checked on macOS

- The full suite passes (14 files, the live debugger test skips).
- Every example outside the debugging parts ran on a live MCP worker.
- Four fresh agents were given only the skill. Two did tasks through the MCP (reading a binary, carrying names from a build with symbols to a stripped one) and got them right. Two wrote Windows debugging scripts that were reviewed and never run.
- On the MCP worker there: the backend is `idat` with IDA's own Python, code runs on the main thread, and imports, variables, `dbg`, breakpoints and handlers survive between calls. A call that raises or times out is cut off and the namespace survives. A result has to be JSON, hence `jsonable`. `close_database` saves and ends the process. `load.py` cannot run in a worker, because `idaapi.require` trips over the worker's stand-in `idapro` module.

Check that these hold on Windows too before leaning on them. They were seen on one machine.

## First steps

1. `git fetch`, then `git switch skill`.
2. `python tests\run.py`. Expect 14 files. `test_outside_skill.py` and the generator have never run on Windows. `python skills\ida-scripts\scripts\api_reference.py --check` should exit 0.
3. See whether this session has the Hex-Rays IDA MCP (its tools are `open_database`, `execute_python`, `close_database`, `save_database`, `list_databases`, `reference`). If it does not, stop and tell the owner. Installing it is the owner's call. Do not stand in another IDA MCP server for it, since the skill is written against this one.
4. Build the live target once: `python tests\run.py debugger_live` from a Developer Command Prompt leaves `tests\.cache\live\ida_scripts_debug_target.exe`. Copy it to a scratch folder and open the copy through the MCP, so its database lands beside the copy. It calls `tick(1)` ten times a second. Its first argument is the number of ticks (600 by default), so start it with something like `args='6000'`.
5. Read `skills/ida-scripts/SKILL.md` and `references/debugging.md` as an agent would, top to bottom, before running anything.

## What to find out

Each of these is a claim in the skill, or a hole in it. Use separate `execute_python` calls where it says so: that is the point. Write down what happened, not what should have.

1. **A session across calls.** Call one: the setup lines from `SKILL.md`, then `dbg.start`. Call two: `dbg.state`, a breakpoint on `tick`, `dbg.resume(timeout=30)`, then `dbg.pc`, `dbg.regs()` and `dbg.stack(8)`. Call three: read `counter`, call `tick` through `dbg.call`, read `counter` again. Is it the same process in all three, with the breakpoint and the variables still there?
2. **A trace inside one call.** A handler on `tick` that appends to a list and returns nothing, then `dbg.resume(timeout=20)`. The skill says this raises `DebuggerError` with `dbg.state == 'running'`, and that the list holds about 200 entries.
3. **Between calls.** After step 2 the process is running. Let half a minute pass with no call, then look at the list. Did the handler run in the meantime, or did the process sit at the breakpoint until the next wait? `debugging.md` tells agents to count on the second. Say which it is in an `idat` worker, and whether `dbg.wait(timeout=…)` picks the process up cleanly either way.
4. **A call the MCP cuts off in the middle of a wait.** Run `dbg.resume(timeout=120)` in an `execute_python` call whose own timeout is 20 seconds. What do the next calls find: does the worker answer, what is `dbg.state`, do `dbg.wait` and `dbg.suspend` work, did the handler survive? This is the path the skill warns about without knowing what it looks like.
5. **Closing with a process attached.** `close_database` while the target is suspended, and once more while it runs. Is the process killed, left hanging, or let go? `tasklist` tells. The skill should say what happens and what to do first.
6. **Ending across calls.** `dbg.detach()` in one call and `dbg.attach(pid)` in a later one, then `dbg.stop()`. Afterwards no copy of the target may be left (`running_copies` and `kill_copies` in `tests/test_debugger_live.py` find and remove them).
7. **The once-a-minute bad open.** On the Mac idalib sometimes opened a database without its root information while an IDA MCP server was running. Watch for anything periodic that disturbs a debugging session that stays open for several minutes.
8. **Installing the skill.** This changes the owner's Claude configuration, so ask first. `claude plugin install ida-scripts --marketplace <path to this clone>` installs from the working copy. Then check that `${CLAUDE_SKILL_DIR}` arrives filled in, that the setup lines find the repository from a Windows path, and that the skill is picked up for a plain request such as "what calls tick in this exe". The README shows `ln -s` for a clone, which is no use on Windows. Write the Windows way in once you have seen one work.
9. **A fresh agent.** Give a subagent the skill and nothing else, and a task with a known answer. For instance: "Through the IDA MCP, debug this program. How often is `tick` called, with what argument, and from where? Then set `counter` to 1000 and show that the program carries on from there. Leave no process behind." And a second one that has to write and run a script: "Trace `tick` for ten seconds and print a summary." Ask each to list what it had to guess or look up. Those lists are the most useful thing a trial gives. On the Mac the MCP kept a record of every call under `~/.idapro/mcp/sessions`, which shows what an agent really ran. Look for the same under IDA's user folder.

Worth doing if they come cheap, and fine to leave with a note:

- What a traced hit costs. `debugging.md` says it is unmeasured. The target pauses 100 ms between ticks, so it cannot tell. A second argument for the pause would let it.
- A program that raises exceptions as part of its normal work, and what `dbg.resume` returns then.
- Adding, disabling and removing breakpoints while the process runs. `debugging.md` says to do it suspended, because nothing else was tried.

## When something does not match

- **The skill is wrong about what happens.** Fix the text. Where `debugging.md` or `SKILL.md` says something has not been run, put what you saw there instead. Add a line for MCP sessions to the table in `tests/README.md`.
- **The library is at fault.** As before: find out what IDA really does with a small script, fix the library, make the fake in `tests/fakes` behave the same, and cover it in `tests/test_debugger.py`.
- **The public API changed.** Run `python skills\ida-scripts\scripts\api_reference.py` and commit the new `api.md` with the change.
- Keep `tests/test_outside_skill.py` passing. It reads every Python block in `SKILL.md` and `debugging.md`, so an example there has to use real names and real arguments.

## How the skill is written

- `SKILL.md` is read in full every time the skill is used, so it stays short. Detail goes into `references/`, with a line in `SKILL.md` that says when to read it.
- It explains why a rule holds, so an agent can handle the case the rule did not foresee. No capitals for emphasis.
- Every claim is something that was seen, or says that it was not. Keep that. An agent cannot tell a guess from a fact unless the text does.
- The owner's Markdown rules: one line per paragraph, list item and quote, and no semicolons in prose.

## Found and left alone

The trials turned these up in the library. They are decisions about its API, so they wait for the owner:

- No helper that names an address as `function+offset` or `module+offset`. `debugging.md` carries a five-line `where(p)` for it.
- `match_functions` cannot say why a function was left out, and a fingerprint ignores operands, so small functions collide.
- `dbg.events` grows by one `Event` for every traced hit.
- No option to take IDA 9.4's argument hints (`f(a1: x)`) out of pseudocode.
- `load.py` cannot run inside an MCP worker.
- `dbg.call` has no time limit.

## Rules

- Debug the test target only, unless the owner names another program. Never leave a process suspended under the debugger.
- No installs or downloads without the owner's word.
- Commits go on this branch: small ones, each `scope: summary` on one line, with no attribution trailer. The owner says when to push and when to merge.
