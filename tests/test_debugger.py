''' `ida_scripts.debugger` against the fake debugger in `tests/fakes`, and the fake against IDA 9.4. '''

import contextlib
import importlib
import inspect
import io
import json
import os
import re
import sys
import time
import types
from unittest import mock

import harness
from harness import sym
from ida_scripts import compat, debugger
import fakes
from fakes import process
from ida_scripts.utils import DebuggerError, IDAError
from ida_scripts.memory import Pointer, ptr
from ida_scripts.module import Module
from ida_scripts.func import Func

D, I = fakes.ida_dbg, fakes.ida_idd
LIB = '/opt/game/libengine.dylib'
LIB_BASE = 0x300000000

class TestFakeMatchesIDA(harness.IDATestCase):
	''' Every name the fake modules define exists in IDA 9.4 with the same parameters and value, and is not deprecated. '''

	COMMON = { '__module__', '__doc__', '__dict__', '__weakref__', '__qualname__', '__firstlineno__', '__static_attributes__' }

	def parameters(self, function) -> list:
		return [(p.name, p.kind, p.default) for p in inspect.signature(function).parameters.values()]

	def deprecated(self, module) -> set:
		with open(module.__file__) as file:
			return set(re.findall(r'^([\w.]+) = ida_idaapi\._ida_deprecated\(', file.read(), re.M))

	def compare(self, fake, real):
		checked = 0
		deprecated = self.deprecated(real)
		for name, value in vars(fake).items():
			if name.startswith('_'):
				continue
			checked += 1
			with self.subTest(f'{real.__name__}.{name}'):
				self.assertTrue(hasattr(real, name), f'{real.__name__} has no {name}')
				self.assertNotIn(name, deprecated)
				target = getattr(real, name)
				if inspect.isfunction(value):
					self.assertEqual(self.parameters(value), self.parameters(target))
				elif inspect.isclass(value):
					self.assertTrue(inspect.isclass(target))
					self.compare_class(value, target)
				elif isinstance(value, (int, str)):
					self.assertEqual(value, target)
				else:
					self.assertEqual(type(value).__name__, type(target).__name__)
		return checked

	def compare_class(self, fake, real):
		for name, value in vars(fake).items():
			if name in self.COMMON or (name.startswith('_') and not name.startswith('__')) or name.startswith(f'_{fake.__name__}__'):
				continue
			self.assertTrue(hasattr(real, name), f'{real.__name__} has no {name}')
			value = getattr(value, '__func__', value)
			if inspect.isfunction(value):
				self.assertEqual(self.parameters(value), self.parameters(getattr(real, name)), f'{real.__name__}.{name}')
		try:
			instance = fake()
		except TypeError:
			return
		for name in vars(instance):
			if not name.startswith('_'):
				self.assertTrue(hasattr(real, name), f'{real.__name__} has no attribute {name}')

	def test_ida_dbg(self):
		import ida_dbg
		self.assertGreater(self.compare(fakes.ida_dbg, ida_dbg), 50)

	def test_ida_idd(self):
		import ida_idd
		self.assertGreater(self.compare(fakes.ida_idd, ida_idd), 25)

class FakeTestCase(harness.IDATestCase):
	''' A test with the fake debugger in place of IDA's, and a fresh `dbg`. '''

	def setUp(self):
		self.ida = process.install(self, process.FakeIDA.for_database())
		self.dbg = debugger.dbg
		self.addCleanup(self.stop)

	def stop(self):
		self.ida.exits_on_request = True
		if self.ida.state != D.DSTATE_NOTASK:
			debugger.dbg.stop()

	def start(self, program=(), **options) -> 'debugger.Event':
		self.ida.program = list(program)
		return self.dbg.start(self.ida.input_path, **options)

	def stopped_at(self, name: str, program=(), tid: int = 1) -> 'debugger.Event':
		''' Start, then resume to a breakpoint at a fixture function. '''
		self.start([('exec', tid, sym(name))] + list(program))
		debugger.Breakpoint.add(sym(name))
		return self.dbg.resume()

class TestNoProcess(FakeTestCase):

	def test_state(self):
		self.assertEqual(self.dbg.state, 'none')
		self.assertIsNone(self.dbg.event)
		self.assertEqual(self.dbg.events, [])
		self.assertEqual(self.dbg.threads, [])
		self.assertEqual(self.dbg.modules, [])

	def test_everything_needs_a_process(self):
		calls = {
			'resuming' : lambda: self.dbg.resume(),
			'waiting' : lambda: self.dbg.wait(),
			'running to' : lambda: self.dbg.run_to('_leaf'),
			'suspending' : lambda: self.dbg.suspend(),
			'detaching' : lambda: self.dbg.detach(),
			'reading register X0' : lambda: self.dbg.reg('X0'),
			'writing register X0' : lambda: self.dbg.reg('X0', 1),
			'reading registers' : lambda: self.dbg.regs(),
			'reading the program counter' : lambda: self.dbg.pc,
			'reading the stack pointer' : lambda: self.dbg.sp,
			'reading the call stack' : lambda: self.dbg.stack(),
			'calling' : lambda: self.dbg.call('_add', 'int add(int a, int b)', 1, 2),
			'selecting thread 1' : lambda: setattr(self.dbg, 'thread', 1),
		}
		for action, call in calls.items():
			with self.subTest(action):
				with self.assertRaisesRegex(DebuggerError, f'{action}.*no process is being debugged'):
					call()

	def test_stop_without_a_process(self):
		self.assertFalse(self.dbg.stop())

	def test_memory_comes_from_the_database(self):
		self.assertEqual(ptr('_counter').u32(), 7)
		with self.assertRaises(DebuggerError):
			ptr('_counter').u32(8)

class TestStart(FakeTestCase):

	def test_start(self):
		event = self.start()
		self.assertEqual(event.kind, 'process_start')
		self.assertEqual(event.module, self.ida.input_path)
		self.assertEqual(event.pid, 4242)
		self.assertEqual(event.tid, 1)
		self.assertEqual(self.dbg.state, 'suspended')
		self.assertIs(self.dbg.event, event)
		self.assertEqual(self.dbg.events, [event])
		self.assertEqual(self.dbg.modules, [Module(self.ida.input_path, self.ida.image_base, self.ida.image_size)])
		self.assertEqual(self.dbg.threads, [1])
		self.assertEqual(self.dbg.thread, 1)
		path, args, cwd = self.ida.calls[[c[0] for c in self.ida.calls].index('start_process')][1:4]
		self.assertEqual((path, args, cwd), (self.ida.input_path, '', os.path.dirname(self.ida.input_path)))

	def test_arguments(self):
		self.ida.program = []
		self.dbg.start(self.ida.input_path, args='"a b" c', cwd='/tmp')
		call = next(c for c in self.ida.calls if c[0] == 'start_process')
		self.assertEqual(call[2:4], ('"a b" c', '/tmp'))

	def test_default_debugger_comes_from_the_database(self):
		self.start()
		self.assertEqual(self.ida.loaded, 'arm_mac')
		self.assertIn(('load_debugger', 'arm_mac', False), self.ida.calls)

	def test_default_debugger_by_file_type(self):
		import ida_ida
		cases = [(ida_ida.f_PE, 'metapc', 'win32'), (ida_ida.f_ELF, 'metapc', 'linux'), (ida_ida.f_MACHO, 'metapc', 'mac'), (ida_ida.f_MACHO, 'ARM', 'arm_mac'), (ida_ida.f_PE, 'ARM', None), (ida_ida.f_BIN, 'metapc', None)]
		for filetype, procname, expected in cases:
			with self.subTest(expected):
				with mock.patch.object(debugger.ida_ida, 'inf_get_filetype', lambda: filetype), mock.patch.object(debugger.ida_ida, 'inf_get_procname', lambda: procname):
					self.assertEqual(debugger.default_debugger(), expected)

	def test_debugger_chosen(self):
		self.start(debugger='win32')
		self.assertEqual(self.ida.loaded, 'win32')

	def test_debugger_the_database_has_is_kept(self):
		self.ida.loaded = 'linux'
		self.start()
		self.assertEqual(self.ida.loaded, 'linux')
		self.assertFalse([c for c in self.ida.calls if c[0] == 'load_debugger'])

	def test_unknown_debugger(self):
		with self.assertRaisesRegex(DebuggerError, "starting .*cannot load its local 'nope' debugger"):
			self.start(debugger='nope')
		self.assertEqual(self.dbg.state, 'none')

	def test_no_debugger_for_the_database(self):
		with mock.patch.object(debugger, 'default_debugger', lambda: None):
			with self.assertRaisesRegex(DebuggerError, 'no local debugger for this database'):
				self.start()

	def test_dialogs_are_off_while_starting(self):
		seen = []
		kernwin = types.SimpleNamespace(cvar=types.SimpleNamespace(batch=0))
		self.ida.on_start = lambda: seen.append(kernwin.cvar.batch)
		with mock.patch.object(debugger, 'ida_kernwin', kernwin):
			self.start()
		self.assertEqual(seen, [1])
		self.assertEqual(kernwin.cvar.batch, 0)
		options = next(c for c in self.ida.calls if c[0] == 'start_process')[4]
		self.assertTrue(options & D.DOPT_START_BPT)
		self.assertEqual(options & D.DOPT_EXCDLG, D.EXCDLG_NEVER)
		self.assertEqual(self.ida.options, 0xa6144)
		waits = [c[1] for c in self.ida.calls if c[0] == 'wait']
		self.assertTrue(all(flags & D.WFNE_SILENT for flags in waits))

	def test_missing_file(self):
		with self.assertRaisesRegex(DebuggerError, 'starting .*no such file'):
			self.dbg.start('/nonexistent/target')
		self.assertFalse([c for c in self.ida.calls if c[0] == 'start_process'])

	def test_already_running(self):
		self.start()
		with self.assertRaisesRegex(DebuggerError, 'already being debugged'):
			self.start()

	def test_refused(self):
		self.ida.start_result = -1
		with self.assertRaisesRegex(DebuggerError, r'starting .*could not create the process \(start_process returned -1\)'):
			self.start()
		self.assertEqual(self.dbg.state, 'none')
		self.ida.start_result = 0
		with self.assertRaisesRegex(DebuggerError, r"IDA did not start it \(start_process returned 0, a cancelled start, and IDA's output says why\)"):
			self.start()

	def test_a_start_that_never_suspends_leaves_no_process(self):
		self.ida.start_suspends = False
		with self.assertRaisesRegex(DebuggerError, 'starting .*still running after 0.01 s'):
			self.start(timeout=0.01)
		self.assertEqual(self.ida.state, D.DSTATE_NOTASK)
		self.assertIn(('exit_process',), self.ida.calls)
		self.assertEqual(self.dbg.event.kind, 'process_exit')

	def test_a_process_that_cannot_be_stopped_is_reported(self):
		self.ida.start_suspends = False
		self.ida.exits_on_request = False
		with self.assertRaisesRegex(DebuggerError, r'still running after 0.01 s \(stopping the process: the process is still there after 0.05 s\)'):
			with mock.patch.object(debugger.Debugger.stop, '__defaults__', (0.05,)):
				self.start(timeout=0.01)

	def test_exit_during_start(self):
		self.ida.start_suspends = False
		with self.assertRaisesRegex(DebuggerError, 'exited at once, with code 3'):
			self.start([('exit', 3)])
		self.assertEqual(self.dbg.state, 'none')

class TestRun(FakeTestCase):

	def test_resume_to_a_breakpoint_and_to_the_end(self):
		compute = sym('compute')
		self.start([('load', LIB, LIB_BASE, 0x1000), ('thread', 2), ('exec', 2, compute), ('exec', 1, sym('leaf')), ('exit', 0)])
		debugger.Breakpoint.add('_compute')
		event = self.dbg.resume()
		self.assertEqual((event.kind, event.address, event.tid), ('breakpoint', compute, 2))
		self.assertEqual(self.dbg.state, 'suspended')
		self.assertEqual(self.dbg.thread, 2)
		self.assertEqual(self.ida.current_tid, 2)
		self.assertEqual([e.kind for e in self.dbg.events], ['process_start', 'library_load', 'thread_start', 'breakpoint'])
		self.assertEqual(self.dbg.events[1].module, LIB)
		self.assertIn(Module(LIB, LIB_BASE, 0x1000), self.dbg.modules)
		end = self.dbg.resume()
		self.assertEqual((end.kind, end.code), ('process_exit', 0))
		self.assertEqual(self.dbg.state, 'none')
		self.assertEqual(self.dbg.modules, [])
		with self.assertRaisesRegex(DebuggerError, 'resuming: no process'):
			self.dbg.resume()

	def test_resume_needs_a_suspended_process(self):
		self.start()
		self.dbg.resume(timeout=0)
		with self.assertRaisesRegex(DebuggerError, 'resuming: the process is running, suspend it first'):
			self.dbg.resume()

	def test_timeout(self):
		self.start()
		with self.assertRaisesRegex(DebuggerError, 'resuming: the process is still running after 0.01 s'):
			self.dbg.resume(timeout=0.01)
		self.assertEqual(self.dbg.state, 'running')
		self.assertTrue(self.dbg.suspend())
		self.assertEqual(self.dbg.state, 'suspended')
		self.assertEqual(self.dbg.event.kind, 'suspended')

	def test_resume_without_waiting(self):
		self.start([('exec', 1, sym('compute'))])
		debugger.Breakpoint.add('_compute')
		self.assertIsNone(self.dbg.resume(timeout=0))
		self.assertEqual(self.dbg.state, 'running')
		self.assertEqual(self.ida.calls[-1], ('wait', D.WFNE_CONT | D.WFNE_NOWAIT | D.WFNE_SILENT, 0))
		event = self.dbg.wait(timeout=1)
		self.assertEqual((event.kind, event.address), ('breakpoint', sym('compute')))

	def test_wait_when_suspended(self):
		event = self.start()
		waits = len([c for c in self.ida.calls if c[0] == 'wait'])
		self.assertIs(self.dbg.wait(), event)
		self.assertEqual(len([c for c in self.ida.calls if c[0] == 'wait']), waits)

	def test_wait_timeout(self):
		self.start()
		self.dbg.resume(timeout=0)
		with self.assertRaisesRegex(DebuggerError, 'waiting: the process is still running after 0 s'):
			self.dbg.wait(timeout=0)

	def test_timeouts_reach_ida(self):
		self.start([('exec', 1, sym('compute'))])
		debugger.Breakpoint.add('_compute')
		self.dbg.resume(timeout=2.5)
		flags, wait_for = [c for c in self.ida.calls if c[0] == 'wait'][-1][1:]
		self.assertTrue(flags & D.WFNE_USEC and flags & D.WFNE_SUSP and flags & D.WFNE_CONT)
		self.assertTrue(2000000 < wait_for <= 2500000)
		self.assertEqual(debugger.wait_time(None), (0, -1))
		self.assertEqual(debugger.wait_time(time.monotonic() + 5000)[0], 0)

	def test_run_to(self):
		self.start([('exec', 1, sym('compute')), ('exec', 1, sym('leaf'))])
		event = self.dbg.run_to('_leaf')
		self.assertEqual((event.kind, event.info, event.address), ('breakpoint', 'run_to', sym('leaf')))
		self.assertIn(('run_to', sym('leaf')), self.ida.calls)
		self.assertEqual(self.dbg.pc, sym('leaf'))

	def test_run_to_stops_at_an_earlier_breakpoint(self):
		self.start([('exec', 1, sym('compute')), ('exec', 1, sym('leaf'))])
		debugger.Breakpoint.add('_compute')
		self.assertEqual(self.dbg.run_to('_leaf').address, sym('compute'))

	def test_suspend(self):
		self.start()
		self.assertTrue(self.dbg.suspend())
		self.dbg.resume(timeout=0)
		self.assertTrue(self.dbg.suspend())
		self.assertEqual((self.dbg.event.kind, self.dbg.state), ('suspended', 'suspended'))
		self.assertIn(('suspend_process',), self.ida.calls)

	def test_stop(self):
		self.start()
		self.assertTrue(self.dbg.stop())
		self.assertEqual(self.dbg.state, 'none')
		self.assertEqual((self.dbg.event.kind, self.dbg.event.code), ('process_exit', -9))
		self.assertFalse(self.dbg.stop())

	def test_stop_a_running_process(self):
		self.start()
		self.dbg.resume(timeout=0)
		self.assertTrue(self.dbg.stop())
		self.assertEqual(self.dbg.state, 'none')

	def test_stop_timeout(self):
		self.start()
		self.ida.exits_on_request = False
		with self.assertRaisesRegex(DebuggerError, 'stopping the process: the process is still there after 0.05 s'):
			self.dbg.stop(timeout=0.05)

	def test_detach(self):
		self.start()
		self.assertTrue(self.dbg.detach())
		self.assertEqual(self.dbg.state, 'none')
		self.assertEqual((self.dbg.event.kind, self.dbg.event.info), ('process_exit', 'detached'))

	def test_attach(self):
		event = self.dbg.attach(4343)
		self.assertEqual((event.kind, event.info, event.pid), ('process_start', 'attached', 4343))
		self.assertEqual(self.dbg.state, 'suspended')
		self.assertEqual(self.dbg.modules[0].name, self.ida.input_path)
		with self.assertRaisesRegex(DebuggerError, 'already being debugged'):
			self.dbg.attach(4343)

	def test_attach_fails(self):
		with self.assertRaisesRegex(DebuggerError, 'attaching to process 1: there is no compatible process with that id'):
			self.dbg.attach(1)
		self.assertEqual(self.dbg.state, 'none')

	def test_exception(self):
		self.start([('exception', 1, sym('compute'), 0xC0000005, 'access violation')])
		event = self.dbg.resume()
		self.assertEqual((event.kind, event.code, event.info, event.address), ('exception', 0xC0000005, 'access violation', sym('compute')))

	def test_events(self):
		self.start([('info', 'hello'), ('load', LIB, LIB_BASE, 0x1000), ('unload', LIB), ('thread', 2), ('thread_exit', 2, 5), ('exit', 1)])
		self.dbg.resume()
		self.assertEqual([e.kind for e in self.dbg.events], ['process_start', 'other', 'library_load', 'library_unload', 'thread_start', 'thread_exit', 'process_exit'])
		self.assertEqual(self.dbg.events[1].info, 'hello')
		self.assertEqual(self.dbg.events[3].module, LIB)
		self.assertEqual((self.dbg.events[5].tid, self.dbg.events[5].code), (2, 5))
		self.dbg.clear_events()
		self.assertEqual(self.dbg.events, [])
		self.assertEqual(self.dbg.event.kind, 'process_exit')

	def test_unloaded_modules_leave_the_list(self):
		self.start([('load', LIB, LIB_BASE, 0x1000), ('unload', LIB), ('exec', 1, sym('compute'))])
		debugger.Breakpoint.add('_compute')
		self.dbg.resume()
		self.assertEqual([m.name for m in self.dbg.modules], [self.ida.input_path])

	def test_json(self):
		event = self.stopped_at('compute')
		data = json.loads(json.dumps(event.to_dict()))
		self.assertEqual(data, { 'kind' : 'breakpoint', 'pid' : 4242, 'tid' : 1, 'address' : hex(sym('compute')), 'module' : None, 'code' : None, 'info' : '' })
		self.assertIn('kind=breakpoint', repr(event))
		self.assertEqual(json.loads(json.dumps(self.dbg.to_dict()))['state'], 'suspended')
		self.assertIsNone(debugger.Event('other', address=compat.BADADDR).address)

class TestHandlers(FakeTestCase):

	def test_a_handler_that_returns_nothing_lets_the_process_run_on(self):
		seen = []
		add = debugger.Breakpoint.add('_add', handler=lambda event: seen.append(event.address))
		self.start([('exec', 1, sym('add'))] * 3 + [('exec', 1, sym('compute'))])
		debugger.Breakpoint.add('_compute')
		event = self.dbg.resume()
		self.assertEqual(event.address, sym('compute'))
		self.assertEqual(seen, [sym('add')] * 3)
		self.assertEqual(add.hits, 3)
		self.assertEqual(debugger.Breakpoint.find('_compute').hits, 1)

	def test_a_handler_that_returns_true_stops(self):
		debugger.Breakpoint.add('_add', handler=lambda event: True)
		self.start([('exec', 1, sym('add'))] * 3)
		self.assertEqual(self.dbg.resume().address, sym('add'))
		self.assertEqual(debugger.Breakpoint.find('_add').hits, 1)

	def test_handlers_read_the_event_thread(self):
		self.ida.main_threads = { 1 : { 'X0' : 11 }, 2 : { 'X0' : 22 } }
		seen = []
		debugger.Breakpoint.add('_add', handler=lambda event: seen.append(self.dbg.reg('X0')))
		self.start([('exec', 2, sym('add')), ('exec', 1, sym('add')), ('exit', 0)])
		self.dbg.resume()
		self.assertEqual(seen, [22, 11])

	def test_a_failing_handler_keeps_the_process_suspended(self):
		def handler(event):
			raise ValueError('handler bug')
		debugger.Breakpoint.add('_add', handler=handler)
		self.start([('exec', 1, sym('add')), ('exit', 0)])
		output = io.StringIO()
		with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
			event = self.dbg.resume()
		self.assertEqual(event.address, sym('add'))
		self.assertEqual(self.dbg.state, 'suspended')
		self.assertIsInstance(self.dbg.handler_error, ValueError)
		self.assertIn('handler bug', output.getvalue())
		self.assertIn('the handler handler failed', output.getvalue())
		self.assertEqual(self.dbg.resume().kind, 'process_exit')
		self.assertIsNone(self.dbg.handler_error)

	def test_handlers_that_keep_the_process_running_hit_the_timeout(self):
		debugger.Breakpoint.add('_add', handler=lambda event: time.sleep(0.01))
		self.start([('exec', 1, sym('add'))] * 100)
		with self.assertRaisesRegex(DebuggerError, 'still running after 0.03 s \\(breakpoint handlers kept it going\\)'):
			self.dbg.resume(timeout=0.03)
		self.assertEqual(self.dbg.state, 'running')
		self.assertLess(debugger.Breakpoint.find('_add').hits, 100)

	def test_handlers_do_not_continue_an_appcall(self):
		hits = []
		debugger.Breakpoint.add('_add', handler=lambda event: hits.append(event))
		def add(a, b):
			# The called function hits the traced breakpoint while Appcall runs the process.
			self.ida.deliver(self.ida.make(I.BREAKPOINT, 1, sym('add')))
			return a + b
		self.ida.functions[sym('add')] = add
		self.stopped_at('compute')
		self.assertEqual(self.dbg.call('_add', 'int add(int a, int b)', 1, 2), 3)
		self.assertEqual(len(hits), 1)
		self.assertFalse([c for c in self.ida.calls if c[0] == 'run_requests'])

	def test_one_hit_is_one_event(self):
		self.start([('exec', 1, sym('compute'))])
		breakpoint = debugger.Breakpoint.add('_compute')
		original = self.ida.make
		def make(eid, tid=None, ea=process.BADADDR):
			event = original(eid, tid, ea)
			if eid == I.BREAKPOINT:
				# IDA can report another address in the event than in the notification (bpt().kea, say).
				hooks = list(self.ida.hooks)
				self.ida.hooks.clear()
				self.ida.event = event
				for hook in hooks:
					hook.dbg_bpt(event.tid, ea)
				self.ida.hooks.extend(hooks)
				event.ea = ea + 1
			return event
		with mock.patch.object(self.ida, 'make', make), mock.patch.object(self.ida, 'deliver', lambda event: setattr(self.ida, 'state', D.DSTATE_SUSP) or setattr(self.ida, 'event', event)):
			self.dbg.resume()
		self.assertEqual(breakpoint.hits, 1)
		self.assertEqual([e.kind for e in self.dbg.events], ['process_start', 'breakpoint'])

	def test_handlers_work_when_the_process_is_resumed_from_ida(self):
		debugger.Breakpoint.add('_add', handler=lambda event: None)
		debugger.Breakpoint.add('_compute')
		self.start([('exec', 1, sym('add')), ('exec', 1, sym('add')), ('exec', 1, sym('compute'))])
		self.ida.pump()
		self.assertEqual(self.dbg.event.address, sym('compute'))
		self.assertEqual(self.dbg.state, 'suspended')
		self.assertEqual(debugger.Breakpoint.find('_add').hits, 2)
		self.assertEqual([c for c in self.ida.calls if c[0] == 'run_requests'], [('run_requests', ['continue'])] * 2)

	def test_on_and_off(self):
		loads, starts = [], []
		self.dbg.on('library_load', loads.append)
		self.dbg.on('thread_start', starts.append)
		self.dbg.on('thread_start', lambda event: starts.append('again'))
		self.start([('load', LIB, LIB_BASE, 0x1000), ('thread', 2), ('exec', 1, sym('compute')), ('load', '/x.dylib', 0x400000000, 0x10), ('thread', 3), ('exit', 0)])
		debugger.Breakpoint.add('_compute')
		self.dbg.resume()
		self.assertEqual([e.module for e in loads], [LIB])
		self.assertEqual(len(starts), 2)
		self.dbg.off('library_load', loads.append)
		self.dbg.off('thread_start')
		self.dbg.resume()
		self.assertEqual(len(loads), 1)
		self.assertEqual(len(starts), 2)
		with self.assertRaisesRegex(ValueError, "unknown event kind 'nope'"):
			self.dbg.on('nope', print)

	def test_a_failing_event_handler_stops_a_tracing_breakpoint(self):
		def broken(event):
			raise RuntimeError('observer bug')
		debugger.Breakpoint.add('_add', handler=lambda event: None)
		self.dbg.on('breakpoint', broken)
		self.start([('exec', 1, sym('add')), ('exit', 0)])
		with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
			event = self.dbg.resume()
		self.assertEqual(event.address, sym('add'))
		self.assertIsInstance(self.dbg.handler_error, RuntimeError)

	def test_events_the_hooks_missed_are_still_recorded(self):
		seen = []
		debugger.Breakpoint.add('_add', handler=lambda event: seen.append(event) or True)
		self.start([('exec', 1, sym('add'))])
		self.dbg._hooks.unhook()
		event = self.dbg.resume()
		self.assertEqual((event.kind, event.address), ('breakpoint', sym('add')))
		self.assertIs(self.dbg.event, event)
		self.assertEqual(seen, [event])

class TestRegisters(FakeTestCase):

	def setUp(self):
		super().setUp()
		self.ida.main_threads = { 1 : { 'X0' : 11, 'X1' : 1, 'SP' : 0x16f000100 }, 2 : { 'X0' : 22, 'X1' : 2, 'SP' : 0x16f800100 } }

	def test_registers_of_the_event_thread(self):
		self.stopped_at('compute', tid=2)
		self.ida.current_tid = 1
		self.assertEqual(self.dbg.reg('X0'), 22)
		self.assertEqual(self.ida.current_tid, 2)
		self.assertEqual(self.dbg.pc, sym('compute'))
		self.assertIsInstance(self.dbg.pc, Pointer)
		self.assertEqual(self.dbg.sp, 0x16f800100)
		self.assertEqual(self.dbg.regs('X0', 'X1'), { 'X0' : 22, 'X1' : 2 })
		everything = self.dbg.regs()
		self.assertEqual(set(everything), set(process.REGISTERS) - { 'V0' })
		self.assertEqual(everything['PC'], sym('compute'))
		self.assertEqual(self.dbg.reg('V0'), bytes(16))
		self.ida.registers.append('LISTED_ONLY')
		self.ida.integer_registers.add('LISTED_ONLY')
		self.assertNotIn('LISTED_ONLY', self.dbg.regs())
		with self.assertRaisesRegex(DebuggerError, 'reading register LISTED_ONLY'):
			self.dbg.regs('X0', 'LISTED_ONLY')

	def test_write(self):
		self.stopped_at('compute', tid=2)
		self.assertTrue(self.dbg.reg('X1', 5))
		self.assertEqual(self.ida.threads[2].regs['X1'], 5)
		self.assertEqual(self.dbg.reg('X1'), 5)
		self.assertFalse(self.dbg.reg('NOPE', 1))

	def test_unknown_register(self):
		self.stopped_at('compute')
		with self.assertRaisesRegex(DebuggerError, 'reading register NOPE of thread 1: Failed to retrieve register value'):
			self.dbg.reg('NOPE')

	def test_select_another_thread(self):
		self.stopped_at('compute', [('exec', 2, sym('compute'))])
		self.assertEqual(self.dbg.threads, [1, 2])
		self.dbg.thread = 2
		self.assertEqual(self.dbg.thread, 2)
		self.assertEqual(self.dbg.reg('X0'), 22)
		with self.assertRaisesRegex(DebuggerError, r'cannot select thread 9: the process has threads \[1, 2\]'):
			self.dbg.thread = 9
		self.dbg.thread = 1
		event = self.dbg.resume()
		self.assertEqual(event.tid, 2)
		self.assertEqual(self.dbg.thread, 2)
		self.assertEqual(self.dbg.reg('X0'), 22)

	def test_registers_need_a_suspended_process(self):
		self.start()
		self.dbg.resume(timeout=0)
		for call in (lambda: self.dbg.reg('X0'), lambda: self.dbg.pc, lambda: self.dbg.stack()):
			with self.assertRaisesRegex(DebuggerError, 'the process is running, suspend it first'):
				call()

	def test_stack(self):
		self.stopped_at('compute')
		self.ida.threads[1].frames = [(sym('compute'), sym('compute')), (sym('main') + 0x20, sym('main'))]
		self.assertEqual(self.dbg.stack(), [sym('compute'), sym('main') + 0x20])
		self.assertEqual(self.dbg.stack(depth=1), [sym('compute')])
		self.assertTrue(all(isinstance(entry, Pointer) for entry in self.dbg.stack()))
		self.ida.threads[1].frames = []
		with self.assertRaisesRegex(DebuggerError, 'cannot collect the call stack of thread 1'):
			self.dbg.stack()

class TestMemoryWhileDebugging(FakeTestCase):

	def setUp(self):
		super().setUp()
		self.ida.copy_database = True

	def test_pointers_read_and_write_the_process(self):
		self.start()
		counter = ptr('_counter')
		self.assertEqual(counter.u32(), 7)
		self.ida.write(counter.addr, (41).to_bytes(4, 'little'))
		self.assertEqual(counter.u32(), 41)
		self.assertTrue(counter.u32(9))
		self.assertEqual(self.ida.read(counter.addr, 4), (9).to_bytes(4, 'little'))
		self.assertTrue(counter.write(b'\x05\x00', verify=True))
		self.assertEqual(counter.swap(b'\x06\x00'), b'\x05\x00')
		self.assertEqual(ptr('_message').ptr().string(), 'pointer target')
		with self.assertRaises(IDAError):
			Pointer(0x10).u32()
		self.assertFalse(Pointer(0x10).write(b'\x00'))
		self.dbg.stop()
		self.assertEqual(counter.u32(), 7)

	def test_pointer_module(self):
		self.start([('load', LIB, LIB_BASE, 0x1000), ('exec', 1, sym('compute'))])
		debugger.Breakpoint.add('_compute')
		self.dbg.resume()
		self.assertEqual(ptr('_counter').module.name, self.ida.input_path)
		self.assertEqual(Pointer(LIB_BASE + 8).module, Module(LIB, LIB_BASE, 0x1000))
		self.assertIsNone(Pointer(0x10).module)
		self.dbg.stop()
		self.assertIsNone(ptr('_counter').module)

class TestCall(FakeTestCase):

	fresh = True

	def setUp(self):
		super().setUp()
		self.ida.main_threads = { 1 : {}, 2 : {} }
		self.ida.functions[sym('add')] = lambda a, b: a + b

	def test_call(self):
		self.stopped_at('compute', tid=2)
		self.ida.current_tid = 1
		self.assertEqual(self.dbg.call('_add', 'int add(int a, int b)', 2, 3), 5)
		self.assertEqual(self.dbg.call(sym('add'), 'int __fastcall add(int a, int b);', 4, 5), 9)
		self.assertEqual(self.dbg.call(Func('_add'), 'int add(int, int)', 1, 1), 2)
		calls = [c for c in self.ida.calls if c[0] == 'appcall']
		self.assertEqual([(c[1], c[2], c[3]) for c in calls], [(sym('add'), 2, (2, 3)), (sym('add'), 2, (4, 5)), (sym('add'), 2, (1, 1))])

	def test_func_call_uses_the_database_prototype(self):
		self.assertTrue(Func('_add').set_prototype('int add(int a, int b)'))
		self.stopped_at('compute')
		self.assertFalse(Func('_add').prototype.endswith(';'))
		self.assertEqual(Func('_add').call(20, 22), 42)
		self.assertEqual([c[3] for c in self.ida.calls if c[0] == 'appcall'], [(20, 22)])

	def test_by_reference_and_wide_arguments(self):
		def fill(out, text):
			out.value = len(text)
			return text
		self.ida.functions[sym('leaf')] = fill
		self.stopped_at('compute')
		out = self.dbg.ref(0)
		self.assertEqual(out.value, 0)
		self.assertEqual(self.dbg.call('_leaf', 'int leaf(int *out, const unsigned short *text)', out, self.dbg.wide('hi')), 'h\0i\0\0\0'.encode('latin-1'))
		self.assertEqual(out.value, 6)
		self.assertEqual(self.dbg.wide('hé'), 'hé\0'.encode('utf-16-le'))

	def test_failures(self):
		self.stopped_at('compute')
		with self.assertRaisesRegex(DebuggerError, "calling 0x.* as 'int add\\(\\(': Could not parse type"):
			self.dbg.call('_add', 'int add((', 1)
		with self.assertRaisesRegex(DebuggerError, 'calling 0x10: the address is not mapped'):
			self.dbg.call(0x10, 'int f(int a)', 1)
		with self.assertRaisesRegex(DebuggerError, 'calling 0x.* failed: Appcall: the process crashed'):
			self.dbg.call('_mul', 'int mul(int a, int b)', 1, 2)
		with self.assertRaises(LookupError):
			self.dbg.call('nope', 'int nope(void)')

	def test_call_needs_a_suspended_process(self):
		self.start()
		self.dbg.resume(timeout=0)
		with self.assertRaisesRegex(DebuggerError, 'calling 0x.*: the process is running'):
			self.dbg.call('_add', 'int add(int a, int b)', 1, 2)

class TestBreakpoints(FakeTestCase):

	def test_add_find_remove(self):
		add = sym('add')
		breakpoint = debugger.Breakpoint.add('_add')
		self.assertEqual(breakpoint.address, add)
		self.assertIsNone(breakpoint.module)
		self.assertIsNone(breakpoint.offset)
		self.assertTrue(breakpoint.enabled)
		self.assertEqual(breakpoint.hits, 0)
		for target in (add, hex(add), Pointer(add), Func('_add')):
			with self.subTest(repr(target)):
				self.assertEqual(debugger.Breakpoint.add(target), breakpoint)
				self.assertEqual(debugger.Breakpoint.find(target), breakpoint)
		self.assertEqual(len(self.ida.bpts), 1)
		self.assertIsNone(debugger.Breakpoint.find('_mul'))
		with self.assertRaises(LookupError):
			debugger.Breakpoint.find('nope')
		self.assertTrue(breakpoint.remove())
		self.assertFalse(breakpoint.remove())
		self.assertIsNone(breakpoint.address)
		self.assertFalse(breakpoint.enabled)
		self.assertEqual(self.ida.bpts, [])

	def test_all_and_clear(self):
		debugger.Breakpoint.add('_add')
		debugger.Breakpoint.add('_mul')
		debugger.Breakpoint.add(0x40, module=LIB)
		self.assertEqual({ b.key for b in debugger.Breakpoint.all() }, { ('abs', sym('add')), ('abs', sym('mul')), ('rel', 'libengine.dylib', 0x40) })
		self.assertEqual(debugger.Breakpoint.clear(), 3)
		self.assertEqual(debugger.Breakpoint.all(), [])
		self.assertEqual(debugger.Breakpoint.clear(), 0)

	def test_breakpoints_set_in_ida_are_listed_and_counted(self):
		D.add_bpt(sym('add'), 0, I.BPT_DEFAULT)
		self.assertEqual([b.address for b in debugger.Breakpoint.all()], [sym('add')])
		self.start([('exec', 1, sym('add'))])
		self.dbg.resume()
		self.assertEqual(debugger.Breakpoint.find('_add').hits, 1)

	def test_enable_and_disable(self):
		breakpoint = debugger.Breakpoint.add('_add')
		breakpoint.enabled = False
		self.assertFalse(breakpoint.enabled)
		self.assertFalse(self.ida.bpts[0]['flags'] & D.BPT_ENABLED)
		self.start([('exec', 1, sym('add')), ('exit', 0)])
		self.assertEqual(self.dbg.resume().kind, 'process_exit')
		breakpoint.enabled = True
		self.assertTrue(breakpoint.enabled)
		breakpoint.remove()
		with self.assertRaisesRegex(DebuggerError, 'cannot enable .*it was removed'):
			breakpoint.enabled = True

	def test_refused(self):
		with mock.patch.object(self.ida, 'add_bpt', lambda *args: False):
			with self.assertRaisesRegex(DebuggerError, 'cannot add a breakpoint at 0x'):
				debugger.Breakpoint.add('_add')
			with self.assertRaisesRegex(DebuggerError, 'cannot add a breakpoint at libx.dylib\\+0x10'):
				debugger.Breakpoint.add(0x10, module='libx.dylib')

	def test_handler(self):
		first, second = lambda e: None, lambda e: True
		breakpoint = debugger.Breakpoint.add('_add', handler=first)
		self.assertIs(breakpoint.handler, first)
		self.assertIs(debugger.Breakpoint.add('_add').handler, first)
		self.assertIs(debugger.Breakpoint.add('_add', handler=second).handler, second)
		breakpoint.handler = None
		self.assertIsNone(debugger.Breakpoint.find('_add').handler)

	def test_module_relative_before_the_module_loads(self):
		seen = []
		breakpoint = debugger.Breakpoint.add(0x40, module='libengine.dylib', handler=lambda event: seen.append(event) or True)
		self.assertIsNone(breakpoint.address)
		self.assertEqual((breakpoint.module, breakpoint.offset, breakpoint.enabled), ('libengine.dylib', 0x40, True))
		self.assertEqual(self.ida.bpts[0]['path'], 'libengine.dylib')
		self.start([('load', LIB, LIB_BASE, 0x10000), ('exec', 1, LIB_BASE + 0x40), ('exit', 0)])
		event = self.dbg.resume()
		self.assertEqual((event.kind, event.address), ('breakpoint', LIB_BASE + 0x40))
		self.assertEqual(seen, [event])
		self.assertEqual(breakpoint.address, LIB_BASE + 0x40)
		self.assertEqual(breakpoint.module, LIB)
		self.assertEqual(breakpoint.hits, 1)
		self.assertEqual(debugger.Breakpoint.find(0x40, module='LIBENGINE.DYLIB'), breakpoint)
		self.assertEqual(debugger.Breakpoint.find(0x40, module=LIB), breakpoint)
		self.assertEqual(debugger.Breakpoint.find(LIB_BASE + 0x40), breakpoint)
		self.assertIsNone(debugger.Breakpoint.find(0x44, module=LIB))
		self.assertEqual(len(self.ida.bpts), 1)

	def test_a_disabled_pending_breakpoint_stays_disabled(self):
		breakpoint = debugger.Breakpoint.add(0x40, module='libengine.dylib')
		breakpoint.enabled = False
		self.start([('load', LIB, LIB_BASE, 0x10000), ('exec', 1, LIB_BASE + 0x40), ('exit', 0)])
		self.assertEqual(self.dbg.resume().kind, 'process_exit')
		self.assertEqual(self.ida.bpts[0]['path'], LIB)
		self.assertFalse(breakpoint.enabled)

	def test_module_relative_in_a_loaded_module(self):
		self.start([('load', LIB, LIB_BASE, 0x10000), ('exec', 1, sym('compute')), ('exec', 1, LIB_BASE + 0x80)])
		debugger.Breakpoint.add('_compute')
		self.dbg.resume()
		breakpoint = debugger.Breakpoint.add(0x80, module='libEngine.dylib')
		self.assertEqual(self.ida.bpts[-1]['path'], LIB)
		self.assertEqual(breakpoint.address, LIB_BASE + 0x80)
		self.assertEqual(self.dbg.resume().address, LIB_BASE + 0x80)

	def test_module_relative_in_the_main_module(self):
		offset = sym('compute') - self.ida.image_base
		breakpoint = debugger.Breakpoint.add(offset, module=os.path.basename(self.ida.input_path))
		self.start([('exec', 1, sym('compute'))])
		self.assertEqual(breakpoint.address, sym('compute'))
		self.assertEqual(self.dbg.resume().address, sym('compute'))

	def test_json(self):
		breakpoint = debugger.Breakpoint.add(0x40, module='libengine.dylib')
		self.assertEqual(json.loads(json.dumps(breakpoint.to_dict())), { 'address' : None, 'module' : 'libengine.dylib', 'offset' : 0x40, 'enabled' : True, 'hits' : 0 })
		self.assertIn('module=libengine.dylib', repr(breakpoint))
		self.assertEqual(debugger.Breakpoint.add('_add').to_dict()['address'], hex(sym('add')))

class TestHooks(FakeTestCase):

	def test_installed_once_on_first_use(self):
		self.assertEqual(self.ida.hooks, [])
		self.dbg.state
		self.assertEqual(len(self.ida.hooks), 1)
		self.dbg.threads
		debugger.Breakpoint.all()
		self.start()
		self.assertEqual(len(self.ida.hooks), 1)
		self.assertEqual(len(self.dbg.events), 1)

	def test_unload_unhooks(self):
		self.dbg.state
		first = self.ida.hooks[0]
		debugger._unload()
		self.assertEqual(self.ida.hooks, [])
		self.dbg.state
		self.assertEqual(len(self.ida.hooks), 1)
		self.assertIsNot(self.ida.hooks[0], first)

	def test_modules_of_a_process_started_before_the_first_use(self):
		self.ida.loaded = 'arm_mac'
		self.ida.options |= D.DOPT_START_BPT
		D.start_process(self.ida.input_path, '', '')
		D.wait_for_next_event(D.WFNE_SUSP, 1)
		self.assertEqual(self.ida.hooks, [])
		self.assertEqual([m.name for m in self.dbg.modules], [self.ida.input_path])
		self.assertIsNone(self.dbg.event)
		self.assertEqual(self.dbg.state, 'suspended')

	def test_reload_replaces_the_hooks(self):
		self.dbg.state
		old = self.ida.hooks[0]
		try:
			with mock.patch.dict(sys.modules, { 'ida_dbg' : D, 'ida_idd' : I }):
				importlib.reload(debugger)
			self.assertEqual(self.ida.hooks, [])
			debugger.dbg.state
			self.assertEqual(len(self.ida.hooks), 1)
			self.assertIsNot(self.ida.hooks[0], old)
			debugger.Breakpoint.add('_compute')
			self.ida.program = [('exec', 1, sym('compute'))]
			debugger.dbg.start(self.ida.input_path)
			self.assertEqual(debugger.dbg.resume().address, sym('compute'))
		finally:
			debugger.dbg.stop()
			debugger._unload()
			importlib.reload(debugger)

	def test_a_fresh_import_unhooks_the_old_copy(self):
		self.dbg.state
		old = self.ida.hooks[0]
		package = sys.modules['ida_scripts']
		original = sys.modules['ida_scripts.debugger']
		with mock.patch.dict(sys.modules, { 'ida_dbg' : D, 'ida_idd' : I }):
			del sys.modules['ida_scripts.debugger']
			try:
				fresh = importlib.import_module('ida_scripts.debugger')
				self.assertIsNot(fresh, original)
				self.assertNotIn(old, self.ida.hooks)
				fresh.dbg.state
				self.assertEqual(len(self.ida.hooks), 1)
				fresh._unload()
				self.assertEqual(self.ida.hooks, [])
			finally:
				package.debugger = original
		self.assertIs(sys.modules['ida_scripts.debugger'], original)

if __name__ == '__main__':
	harness.main()
