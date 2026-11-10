''' `ida_scripts.debugger` against a real process under IDA's local debugger.

Builds `tests/fixtures/live/debug_target.c` with the first C compiler it finds, opens a fresh database of it, and debugs it step by step: start, a breakpoint by name, registers, memory, a call into the process, a module-relative breakpoint, handlers, `run_to` and `stop`.

A first start is tried in a child process with a time limit. When the system refuses to let IDA debug (macOS without the needed permissions, say), every step is skipped with the reason IDA gave, and nothing is left running. Each step after a failed one is skipped too, naming the step that failed.

Run alone with `python tests/run.py debugger_live`.
'''

import contextlib
import csv
import functools
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import warnings

import harness
from ida_scripts import compat
from ida_scripts.utils import DebuggerError
from ida_scripts.memory import Pointer
from ida_scripts.module import Module
from ida_scripts import debugger

TARGET = 'ida_scripts_debug_target'
SOURCE = os.path.join(harness.TESTS, 'fixtures', 'live', 'debug_target.c')
WINDOWS = sys.platform == 'win32'
EXECUTABLE = TARGET + ('.exe' if WINDOWS else '')
REPORT = TARGET + '.report'
TICKS = 600
PREFLIGHT_TIMEOUT = 180
STEP_TIMEOUT = 30

# BUILD

def build() -> tuple:
	''' Compile the target into the test cache. Returns `(path, '')`, or `(None, why not)`. '''
	folder = os.path.join(harness.CACHE, 'live')
	os.makedirs(folder, exist_ok=True)
	binary = os.path.join(folder, EXECUTABLE)
	if os.path.exists(binary) and os.path.getmtime(binary) >= os.path.getmtime(SOURCE):
		return binary, ''
	if WINDOWS:
		compilers = ['cl', 'clang', 'gcc']
	elif sys.platform == 'darwin':
		compilers = ['clang']
	else:
		compilers = ['clang', 'gcc', 'cc']
	failures = []
	for compiler in compilers:
		path = shutil.which(compiler)
		if not path:
			continue
		if compiler == 'cl':
			# No incremental linking: it would put tick behind a jump thunk.
			command = [path, '/nologo', '/Od', '/Zi', f'/Fe{binary}', f'/Fo{folder}{os.sep}', f'/Fd{folder}{os.sep}', SOURCE, '/link', '/INCREMENTAL:NO']
		else:
			command = [path, '-O0', '-g', '-o', binary, SOURCE]
		try:
			result = subprocess.run(command, cwd=folder, capture_output=True, text=True, errors='replace', timeout=300)
		except (OSError, subprocess.TimeoutExpired) as error:
			failures.append(f'{compiler}: {error}')
			continue
		if result.returncode == 0 and os.path.exists(binary):
			return binary, ''
		failures.append(f'{compiler} exited with {result.returncode}: {(result.stdout + result.stderr).strip()[-500:]}')
	if not failures:
		return None, f'no C compiler found to build {SOURCE} (looked for {", ".join(compilers)} on PATH)'
	return None, f'no C compiler could build {SOURCE}: ' + ' | '.join(failures)

# PROCESSES

def running_copies() -> list:
	''' Ids of the running copies of the target, found by file name. '''
	try:
		if WINDOWS:
			listing = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'], capture_output=True, text=True, errors='replace', timeout=60).stdout
			return [int(row[1]) for row in csv.reader(listing.splitlines()) if len(row) > 1 and row[0].lower() == EXECUTABLE.lower()]
		listing = subprocess.run(['ps', '-A', '-o', 'pid=', '-o', 'args='], capture_output=True, text=True, errors='replace', timeout=60).stdout
	except (OSError, subprocess.TimeoutExpired):
		return []
	pids = []
	for line in listing.splitlines():
		pid, _, args = line.strip().partition(' ')
		if args.strip() and os.path.basename(args.split()[0]) == EXECUTABLE:
			pids.append(int(pid))
	return pids

def kill_copies() -> list:
	''' Kill every running copy of the target. Returns their ids. '''
	pids = running_copies()
	for pid in pids:
		try:
			os.kill(pid, getattr(signal, 'SIGKILL', signal.SIGTERM))
		except OSError:
			pass
	return pids

# DATABASE

def open_copy(binary: str) -> tuple:
	''' Copy the target into a new temporary folder and open a fresh database of it there. Returns `(database, folder, path of the copy)`. '''
	from ida_scripts.session import Database
	folder = tempfile.mkdtemp(prefix='ida_scripts_live_')
	target = os.path.join(folder, EXECUTABLE)
	shutil.copy2(binary, target)
	return Database.open(target, analyze=True), folder, target

def choose_debugger() -> str:
	''' The debugger to use: `None` when the database already has one, else the local one for this platform. '''
	import ida_dbg
	if ida_dbg.dbg_is_loaded():
		return None
	if WINDOWS:
		return 'win32'
	if sys.platform == 'darwin':
		# IDA's local debugger for arm64 macOS is arm_mac. 'mac' is for Intel Macs (and remote).
		return 'arm_mac' if platform.machine() == 'arm64' else 'mac'
	return 'linux'

def symbol(name: str):
	''' The database's name for a C symbol of the target (`tick` or `_tick`), `None` when it has neither. '''
	import ida_name
	for candidate in (name, '_' + name):
		if ida_name.get_name_ea(compat.BADADDR, candidate) != compat.BADADDR:
			return candidate
	return None

def scratch_register() -> str:
	''' A caller-saved integer register of the database's architecture, safe to change and restore at a function's entry. '''
	import ida_ida
	processor, wide = ida_ida.inf_get_procname(), compat.is_64bit()
	if processor == 'metapc':
		return 'RAX' if wide else 'EAX'
	if processor == 'ARM':
		return 'X9' if wide else 'R12'
	return None

def preflight(binary: str):
	''' In a child process: try one start, print the outcome as a JSON line, and leave nothing running. '''
	import idapro
	from ida_scripts.debugger import dbg
	result = { 'ok' : False, 'error' : '' }
	folder = None
	try:
		database, folder, target = open_copy(binary)
		idapro.enable_console_messages(True)
		try:
			dbg.start(target, args=str(TICKS), debugger=choose_debugger(), timeout=60)
			result['ok'] = True
		except DebuggerError as error:
			result['error'] = str(error)
		finally:
			try:
				dbg.stop()
			except DebuggerError as error:
				result['error'] += f' (then stopping it failed: {error})'
			database.close()
	except Exception as error:
		result['error'] = f'{type(error).__name__}: {error}'
	finally:
		if folder:
			shutil.rmtree(folder, ignore_errors=True)
	print('PREFLIGHT ' + json.dumps(result), flush=True)

def try_debugging(binary: str) -> str:
	''' Start the target once in a child process. Returns `''` when that worked, else why not, with what IDA printed. '''
	try:
		child = subprocess.run([sys.executable, '-u', __file__, '--preflight', binary], capture_output=True, text=True, errors='replace', timeout=PREFLIGHT_TIMEOUT)
	except subprocess.TimeoutExpired as expired:
		left = kill_copies()
		output = expired.stdout.decode(errors='replace') if isinstance(expired.stdout, bytes) else (expired.stdout or '')
		return f'starting the target under IDA\'s local debugger did not finish within {PREFLIGHT_TIMEOUT} s (killed {len(left)} copies of it). IDA said: {said(output)}'
	output = child.stdout + child.stderr
	line = next((l for l in output.splitlines() if l.startswith('PREFLIGHT ')), None)
	left = kill_copies()
	if line is None:
		return f'the child process that tries a start exited with {child.returncode} without a result. Its output: {said(output)}'
	result = json.loads(line[len('PREFLIGHT '):])
	if result['ok']:
		if left:
			print(f'test_debugger_live: the trial start worked but left copies of the target running, killed: {left}', file=sys.stderr)
		return ''
	return f'IDA could not debug the target on this machine: {result["error"]}. IDA said: {said(output)}'

def said(output: str) -> str:
	lines = [l.strip() for l in output.splitlines() if l.strip() and not l.startswith('PREFLIGHT ')]
	return ' | '.join(lines[-15:]) or '(nothing)'

def step(function):
	''' One step of the session: skipped when an earlier step failed, and marks the session broken when it fails itself. '''
	@functools.wraps(function)
	def run(self):
		if type(self).broken:
			self.skipTest(f'an earlier step failed: {type(self).broken}')
		try:
			function(self)
		except unittest.SkipTest:
			raise
		except BaseException:
			type(self).broken = function.__name__
			raise
	return run

class TestLiveDebugging(unittest.TestCase):

	broken = ''
	database = None
	folder = None

	@classmethod
	def setUpClass(cls):
		binary, problem = build()
		if problem:
			cls.skip(problem)
		problem = try_debugging(binary)
		if problem:
			cls.skip(problem)
		cls.database, cls.folder, cls.target = open_copy(binary)
		warnings.simplefilter('error', DeprecationWarning)
		import idapro
		idapro.enable_console_messages(True)
		cls.debugger = choose_debugger()
		cls.dbg = debugger.dbg
		cls.session = {}

	@classmethod
	def skip(cls, reason: str):
		print(f'test_debugger_live skipped: {reason}', file=sys.stderr, flush=True)
		raise unittest.SkipTest(reason)

	@classmethod
	def tearDownClass(cls):
		if cls.database is None:
			return
		try:
			cls.dbg.stop()
		except DebuggerError as error:
			print(f'test_debugger_live: stopping the target at the end failed: {error}', file=sys.stderr)
		debugger.Breakpoint.clear()
		left = kill_copies()
		if left:
			print(f'test_debugger_live: killed copies of the target left running: {left}', file=sys.stderr)
		cls.database.close()
		shutil.rmtree(cls.folder, ignore_errors=True)

	@contextlib.contextmanager
	def doing(self, what: str):
		''' Turn an exception into a failure that says what was attempted. '''
		try:
			yield
		except AssertionError:
			raise
		except Exception as error:
			self.fail(f'{what}: {type(error).__name__}: {error}')

	def report(self) -> dict:
		''' What the target wrote at its start: pid, tick count, and the runtime addresses of tick and counter. '''
		path = os.path.join(self.folder, REPORT)
		deadline = time.monotonic() + STEP_TIMEOUT
		text = ''
		while not text:
			if os.path.exists(path):
				with open(path) as file:
					text = file.read().strip()
			if not text:
				self.assertLess(time.monotonic(), deadline, f'the target writes {path} when main starts, within {STEP_TIMEOUT} s')
				time.sleep(0.1)
		pid, ticks, tick, counter = text.split()
		return { 'pid' : int(pid), 'ticks' : int(ticks), 'tick' : int(tick, 16), 'counter' : int(counter, 16) }

	@step
	def test_01_start(self):
		which = f'the {self.debugger} debugger' if self.debugger else 'the debugger the database has'
		with self.doing(f'starting {self.target} with {which}'):
			event = self.dbg.start(self.target, args=str(TICKS), debugger=self.debugger, timeout=60)
		self.assertEqual(event.kind, 'process_start', f'start() returns the process_start event, got {event}')
		self.assertEqual(self.dbg.state, 'suspended', 'the process is suspended after start()')
		self.assertGreater(event.pid, 0, f'the start event has the process id, got {event}')
		self.assertIn(event.tid, self.dbg.threads, f'the start event\'s thread {event.tid} is one of the threads {self.dbg.threads}')
		main = Module.find(EXECUTABLE)
		self.assertIsNotNone(main, f'Module.find({EXECUTABLE!r}) finds the target among {Module.all_modules()}')
		self.assertTrue(main.is_input_file, f'{main} is the database\'s input file')
		self.assertIn(main, self.dbg.modules, f'dbg.modules {self.dbg.modules} has the target module, recorded from the start event')
		self.session['main'] = main

	@step
	def test_02_breakpoint_by_name(self):
		tick = symbol('tick')
		if tick is None:
			# No name in the database: let main write the report, then use the address it gives.
			with self.doing('resuming without waiting, to let main write its report'):
				self.dbg.resume(timeout=0)
			report = self.report()
			with self.doing('suspending the process'):
				self.assertTrue(self.dbg.suspend(), 'suspend() suspends the running target')
			tick = report['tick']
			print(f'test_debugger_live: the database has no name for tick, using the address the target reports, {hex(tick)}', file=sys.stderr)
		with self.doing(f'adding a breakpoint at {tick!r}'):
			breakpoint = debugger.Breakpoint.add(tick)
		self.assertIsNotNone(breakpoint.address, f'the breakpoint at {tick!r} has an address')
		with self.doing('resuming to the breakpoint at tick'):
			event = self.dbg.resume(timeout=STEP_TIMEOUT)
		self.assertEqual(event.kind, 'breakpoint', f'resume() stops at the breakpoint at tick, got {event}')
		self.assertEqual(event.address, breakpoint.address, f'the event is at the breakpoint {breakpoint}, got {event}')
		self.assertEqual(breakpoint.hits, 1, f'the breakpoint counts its hit: {breakpoint}')
		self.assertEqual(self.dbg.thread, event.tid, f'the event\'s thread {event.tid} is selected after resume()')
		self.session.update(tick=tick, tick_address=breakpoint.address.addr, breakpoint=breakpoint)

	@step
	def test_03_registers(self):
		with self.doing('reading the program counter'):
			pc = self.dbg.pc
		self.assertEqual(pc, self.session['tick_address'], f'dbg.pc is the breakpoint address {hex(self.session["tick_address"])} at the hit, got {pc}')
		with self.doing('reading the stack pointer'):
			sp = self.dbg.sp
		self.assertNotEqual(sp.addr, 0, 'dbg.sp is not zero')
		size = 8 if compat.is_64bit() else 4
		with self.doing(f'reading {size} bytes at the stack pointer {sp}'):
			self.assertEqual(len(sp.read(size)), size, f'the memory at dbg.sp {sp} is readable')
		name = scratch_register()
		self.assertIsNotNone(name, 'a scratch register is known for this processor')
		with self.doing(f'reading register {name}'):
			original = self.dbg.reg(name)
		self.assertIsInstance(original, int, f'register {name} reads as an int, got {original!r}')
		with self.doing(f'writing register {name}'):
			self.assertTrue(self.dbg.reg(name, 0x1234), f'writing {name} succeeds')
			self.assertEqual(self.dbg.reg(name), 0x1234, f'{name} reads back what was written')
			self.assertTrue(self.dbg.reg(name, original), f'restoring {name} succeeds')
			self.assertEqual(self.dbg.reg(name), original, f'{name} is restored')
		with self.doing('reading all integer registers'):
			values = self.dbg.regs()
		self.assertIn(name, values, f'dbg.regs() has {name}: {sorted(values)}')
		self.assertEqual(self.dbg.regs(name), { name : original }, f'dbg.regs({name!r}) reads that register')
		with self.doing('reading the call stack'):
			stack = self.dbg.stack()
		self.assertTrue(stack, 'dbg.stack() has at least the current frame')
		self.assertEqual(stack[0], pc, f'dbg.stack() starts at the program counter {pc}, got {stack}')

	@step
	def test_04_memory(self):
		report = self.report()
		self.assertEqual(report['ticks'], TICKS, f'the target got its argument {TICKS} through start(args=...)')
		counter = symbol('counter')
		if counter is not None:
			self.assertEqual(Pointer(counter).addr, report['counter'], f'the database address of {counter} matches the address the target reports, so IDA rebased the database to the process')
		address = Pointer(report['counter'])
		with self.doing(f'reading counter at {address}'):
			value = address.u32()
		self.assertLess(value, TICKS, f'counter {value} counts the calls of tick so far')
		with self.doing(f'writing counter at {address}'):
			self.assertTrue(address.u32(value + 1000), 'writing counter succeeds')
			self.assertEqual(address.u32(), value + 1000, 'counter reads back what was written')
			self.assertTrue(address.write((value + 2000).to_bytes(4, 'little' if not compat.is_big_endian() else 'big'), verify=True), 'a verified raw write succeeds')
		with self.doing('resuming to the next call of tick'):
			event = self.dbg.resume(timeout=STEP_TIMEOUT)
		self.assertEqual(event.address, self.session['tick_address'], f'the next hit is at tick again, got {event}')
		self.assertEqual(address.u32(), value + 2001, 'the process saw the written counter: one more tick added 1 to it')
		self.assertEqual(self.session['breakpoint'].hits, 2, f'the breakpoint counted two hits: {self.session["breakpoint"]}')
		self.session['counter'] = address

	@step
	def test_05_call(self):
		breakpoint, counter = self.session['breakpoint'], self.session['counter']
		before = counter.u32()
		with self.doing('disabling the breakpoint at tick before calling it'):
			breakpoint.enabled = False
		self.assertFalse(breakpoint.enabled, 'the breakpoint is disabled')
		with self.doing('calling tick(5) in the process'):
			result = self.dbg.call(self.session['tick'], 'int tick(int step)', 5)
		with self.doing('enabling the breakpoint again'):
			breakpoint.enabled = True
		self.assertEqual(result, before + 5, f'tick(5) returns the counter plus 5 ({before} + 5), got {result!r}')
		self.assertEqual(counter.u32(), before + 5, 'the call changed counter in the process')
		self.assertEqual(self.dbg.state, 'suspended', 'the process is suspended again after the call')
		self.assertEqual(self.dbg.pc, self.session['tick_address'], 'the call left the thread where it was')

	@step
	def test_06_module_relative_breakpoint(self):
		main, address = self.session['main'], self.session['tick_address']
		with self.doing('removing the breakpoint at tick'):
			self.assertTrue(self.session['breakpoint'].remove(), 'the absolute breakpoint is removed')
		offset = address - main.addr
		with self.doing(f'adding a breakpoint at {EXECUTABLE}+{hex(offset)}'):
			relative = debugger.Breakpoint.add(offset, module=EXECUTABLE)
		self.assertEqual(relative.offset, offset, f'the breakpoint keeps its offset: {relative}')
		self.assertEqual(relative.address, address, f'the module-relative breakpoint resolves to tick at {hex(address)}: {relative}')
		with self.doing('resuming to the module-relative breakpoint'):
			event = self.dbg.resume(timeout=STEP_TIMEOUT)
		self.assertEqual(event.address, address, f'the module-relative breakpoint stops at tick, got {event}')
		self.assertEqual(relative.hits, 1, f'the module-relative breakpoint counts its hit: {relative}')
		pc = self.dbg.pc
		self.assertEqual(Module.containing(pc), main, f'the program counter {pc} is inside {main}')
		self.assertEqual(main.from_static(main.to_static(pc)), pc, 'to_static and from_static undo each other')
		self.session['relative'] = relative

	@step
	def test_07_handlers(self):
		relative, seen = self.session['relative'], []
		relative.handler = lambda event: seen.append(event.address)
		with self.assertRaises(DebuggerError, msg='resume() times out while a handler that returns None keeps the process going'):
			self.dbg.resume(timeout=2)
		self.assertGreaterEqual(len(seen), 3, f'the tracing handler saw several calls of tick in 2 s, saw {len(seen)}')
		self.assertTrue(all(address == relative.address for address in seen), 'every hit the handler saw is at tick')
		with self.doing('suspending the traced process'):
			self.assertTrue(self.dbg.suspend(), 'suspend() suspends the process the handler kept running')
		relative.handler = lambda event: True
		events = []
		# A suspension can leave an event of its own for the next resume (Windows pauses a process by making it break in a new thread).
		while len(events) < 3 and (not events or events[-1].address != relative.address):
			with self.doing('resuming with a handler that returns True'):
				events.append(self.dbg.resume(timeout=STEP_TIMEOUT))
		self.assertEqual(events[-1].address, relative.address, f'a handler that returns True stops at the hit, got {events}')
		self.assertIsNone(self.dbg.handler_error, f'no handler failed: {self.dbg.handler_error!r}')

	@step
	def test_08_run_to(self):
		with self.doing('removing the module-relative breakpoint'):
			self.assertTrue(self.session['relative'].remove(), 'the module-relative breakpoint is removed')
		self.assertEqual(debugger.Breakpoint.all(), [], 'no breakpoint is left')
		with self.doing('running to tick'):
			event = self.dbg.run_to(self.session['tick'], timeout=STEP_TIMEOUT)
		self.assertEqual(event.address, self.session['tick_address'], f'run_to(tick) stops at tick, got {event}')
		self.assertEqual(self.dbg.state, 'suspended', 'the process is suspended after run_to()')

	@step
	def test_09_stop(self):
		pid = self.report()['pid']
		with self.doing('stopping the process'):
			self.assertTrue(self.dbg.stop(), 'stop() ends the process')
		self.assertEqual(self.dbg.state, 'none', 'no process is debugged after stop()')
		self.assertEqual(self.dbg.event.kind, 'process_exit', f'stop() records the process_exit event, got {self.dbg.event}')
		self.assertFalse(self.dbg.stop(), 'a second stop() has nothing to stop')
		deadline = time.monotonic() + 10
		while pid in running_copies() and time.monotonic() < deadline:
			time.sleep(0.2)
		self.assertNotIn(pid, running_copies(), f'the target (pid {pid}) is gone within 10 s of stop()')

if __name__ == '__main__':
	if len(sys.argv) == 3 and sys.argv[1] == '--preflight':
		preflight(sys.argv[2])
	else:
		harness.main()
