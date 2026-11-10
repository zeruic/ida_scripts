''' The simulated debugger and process behind the fake `ida_dbg` and `ida_idd`.

The process runs a `program`: a list of steps, taken one by one while it runs, each of which may produce an event.

- `('exec', tid, ea)`: thread `tid` reaches `ea`. An event when a breakpoint or the target of `run_to` is there.
- `('load', path, base, size)`, `('unload', path)`: a library loads or unloads.
- `('thread', tid)`, `('thread_exit', tid, code)`: a thread starts or exits.
- `('exception', tid, ea, code, info)`, `('info', text)`, `('exit', code)`.
- `('call', function)`: runs `function(fake)`, as the program doing something, and produces no event.

When the program runs out, the process runs forever: waits time out.

The model follows IDA 9.4 as it was observed debugging a real process with the win32 debugger: which notifications come and in what order, what the events carry, how a module-relative breakpoint finds its module, and what the breakpoint calls return. Otherwise it follows the documentation of the stubs.

It is stricter than IDA in one thing: IDA selects the thread of an event and the fake does not, so the module has to. `places_by_file_name` turns off what only the win32 debugger is known to do.
'''

import sys
from unittest import mock

from . import ida_dbg as D
from . import ida_idd as I

current: 'FakeIDA' = None
''' The simulation the fake modules talk to. '''

REGISTERS = ['X0', 'X1', 'X2', 'X8', 'X29', 'X30', 'SP', 'PC', 'V0']
BADADDR = 0xFFFFFFFFFFFFFFFF

class Thread:
	''' A thread of the simulated process. '''

	def __init__(self, tid: int, regs: dict = None, frames: list = None):
		self.tid = tid
		self.regs = { name : 0 for name in REGISTERS }
		self.regs['V0'] = bytes(16)
		self.regs.update(regs or {})
		self.frames = list(frames or [])

class FakeIDA:
	''' IDA's debugger kernel and one debugged process, simulated. '''

	def __init__(self, input_path: str, image_base: int, image_size: int):
		self.input_path = input_path
		self.image_base = image_base
		self.image_size = image_size
		self.main_base = image_base
		self.debuggers = { 'arm_mac', 'mac', 'win32', 'linux' }
		self.loaded = None
		self.options = 0xa6144
		self.state = D.DSTATE_NOTASK
		self.hooks = []
		self.bpts = []
		self.modules = []
		self.memory = []
		self.threads = {}
		self.current_tid = 0
		self.event = I.debug_event_t()
		self.pid = 0
		self.program = []
		self.requests = []
		self.ui_requests = []
		self.run_to_target = None
		self.registers = list(REGISTERS)
		self.integer_registers = set(REGISTERS) - { 'V0' }
		self.functions = {}
		self.calls = []
		self.on_start = None
		# How the simulated system behaves: the tests change these.
		self.start_result = 1
		self.start_suspends = True
		self.attachable = 4343
		self.exits_on_request = True
		self.lists_modules = True
		self.places_by_file_name = True
		self.main_threads = { 1 : {} }
		self.loaded_before = []
		self.process_memory = []
		self.copy_database = False

	@staticmethod
	def for_database() -> 'FakeIDA':
		''' A simulation for the open database: its input file is the main module, at the image base. '''
		import ida_nalt
		import ida_ida
		from ida_scripts import compat
		return FakeIDA(ida_nalt.get_input_file_path(), compat.image_base(), ida_ida.inf_get_max_ea() - compat.image_base())

	# PROCESS
	def load_debugger(self, name, remote):
		self.calls.append(('load_debugger', name, remote))
		if name not in self.debuggers or remote:
			return False
		self.loaded = name
		return True

	def start_process(self, path, args, sdir):
		self.calls.append(('start_process', path, args, sdir, self.options))
		if self.on_start:
			self.on_start()
		if self.loaded is None:
			return -1
		if self.start_result != 1:
			return self.start_result
		self.launch()
		self.program.insert(0, ('start',))
		return 1

	def attach_process(self, pid, event_id=-1):
		self.calls.append(('attach_process', pid, event_id))
		if self.loaded is None:
			return -4
		if pid != self.attachable:
			# Observed: -1 for a process id that does not exist, not -2.
			return -1
		self.launch(pid)
		self.program.insert(0, ('attach',))
		return 1

	def launch(self, pid: int = 4242):
		self.state = D.DSTATE_RUN
		self.pid = pid
		self.threads = { tid : Thread(tid, regs) for tid, regs in self.main_threads.items() }
		self.current_tid = min(self.threads)
		self.memory = [[base, bytearray(data)] for base, data in self.process_memory]
		if self.copy_database:
			self.memory += database_memory()

	def request(self, kind):
		self.calls.append((f'{kind}_process',))
		if self.state == D.DSTATE_NOTASK:
			# Observed: exit_process() reports success even without a process.
			return kind == 'exit'
		if kind == 'suspend' and self.state == D.DSTATE_SUSP:
			return True
		self.requests.append(kind)
		return True

	def continue_process(self):
		if self.state == D.DSTATE_SUSP:
			self.state = D.DSTATE_RUN
		return True

	def run_requests(self):
		self.calls.append(('run_requests', list(self.ui_requests)))
		while self.ui_requests:
			if self.ui_requests.pop(0) == 'continue':
				self.continue_process()
		return True

	def run_to(self, ea):
		self.calls.append(('run_to', ea))
		if self.state != D.DSTATE_SUSP:
			return False
		self.run_to_target = ea
		self.state = D.DSTATE_RUN
		return True

	def end(self):
		self.state = D.DSTATE_NOTASK
		self.modules, self.threads, self.memory, self.requests = [], {}, [], []
		self.current_tid, self.pid, self.run_to_target = 0, 0, None

	# EVENTS
	def make(self, eid, tid=None, ea=BADADDR):
		event = I.debug_event_t()
		event._eid, event.pid, event.ea = eid, self.pid, ea
		event.tid = self.current_tid if tid is None else tid
		return event

	def next_event(self):
		while self.requests:
			kind = self.requests.pop(0)
			if kind == 'suspend':
				return self.make(I.PROCESS_SUSPENDED, ea=self.threads[self.current_tid].regs['PC'])
			if kind == 'detach':
				# Observed: the detach event names no process and no thread.
				event = self.make(I.PROCESS_DETACHED, 0)
				event.pid = -1
				return event
			if self.exits_on_request:
				event = self.make(I.PROCESS_EXITED)
				event._exit_code = -9
				return event
		while self.program:
			event = self.execute(self.program.pop(0))
			if event is not None:
				return event
		return None

	def execute(self, step):
		kind, args = step[0], step[1:]
		if kind in ('start', 'attach'):
			# Observed: the start event has no address. An attach has the address its thread is at.
			event = self.make(I.PROCESS_STARTED, ea=BADADDR) if kind == 'start' else self.make(I.PROCESS_ATTACHED, ea=self.main_base)
			self.loaded_module(event, self.input_path, self.main_base, self.image_size)
			if kind == 'attach':
				# Observed: the libraries a process has when it is attached to are listed, and no load event comes for them.
				self.modules += [list(module) for module in self.loaded_before]
			return event
		if kind == 'load':
			event = self.make(I.LIB_LOADED, ea=args[1])
			self.loaded_module(event, *args)
			return event
		if kind == 'unload':
			module = next(m for m in self.modules if m[0] == args[0])
			self.modules.remove(module)
			event = self.make(I.LIB_UNLOADED, ea=module[1])
			event._info = args[0]
			return event
		if kind == 'thread':
			self.threads[args[0]] = Thread(args[0])
			return self.make(I.THREAD_STARTED, args[0])
		if kind == 'thread_exit':
			self.threads.pop(args[0])
			event = self.make(I.THREAD_EXITED, args[0])
			event._exit_code = args[1]
			return event
		if kind == 'exec':
			tid, ea = args
			self.threads[tid].regs['PC'] = ea
			if any(self.resolved(b) == ea and b['flags'] & D.BPT_ENABLED for b in self.bpts):
				return self.make(I.BREAKPOINT, tid, ea)
			if self.run_to_target == ea:
				self.run_to_target = None
				event = self.make(I.BREAKPOINT, tid, ea)
				event._run_to = True
				return event
			return None
		if kind == 'exception':
			tid, ea, code, info = args
			event = self.make(I.EXCEPTION, tid, ea)
			event._exc.code, event._exc.info, event._exc.ea = code, info, ea
			return event
		if kind == 'info':
			event = self.make(I.INFORMATION)
			event._info = args[0]
			return event
		if kind == 'exit':
			event = self.make(I.PROCESS_EXITED)
			event._exit_code = args[0]
			return event
		if kind == 'call':
			args[0](self)
			return None
		raise ValueError(f'unknown step {step}')

	def loaded_module(self, event, path, base, size):
		self.modules.append([path, base, size])
		event._modinfo.name, event._modinfo.base, event._modinfo.size = path, base, size

	def deliver(self, event):
		''' Make `event` the current one: suspend the process when it should, and notify the hooks. '''
		self.event = event
		eid = event.eid()
		suspends = eid in (I.BREAKPOINT, I.EXCEPTION, I.PROCESS_SUSPENDED, I.PROCESS_ATTACHED)
		suspends |= eid == I.PROCESS_STARTED and bool(self.options & D.DOPT_START_BPT) and self.start_suspends
		suspends |= eid == I.LIB_LOADED and bool(self.options & D.DOPT_LIB_BPT)
		if suspends:
			self.state = D.DSTATE_SUSP
		pid, tid, ea = event.pid, event.tid, event.ea
		info = event.modinfo()
		for hook in list(self.hooks):
			if eid == I.PROCESS_STARTED:
				hook.dbg_process_start(pid, tid, ea, info.name, info.base, info.size)
			elif eid == I.PROCESS_ATTACHED:
				hook.dbg_process_attach(pid, tid, ea, info.name, info.base, info.size)
			elif eid == I.PROCESS_EXITED:
				hook.dbg_process_exit(pid, tid, ea, event.exit_code())
			elif eid == I.PROCESS_DETACHED:
				hook.dbg_process_detach(pid, tid, ea)
			elif eid == I.THREAD_STARTED:
				hook.dbg_thread_start(pid, tid, ea)
			elif eid == I.THREAD_EXITED:
				hook.dbg_thread_exit(pid, tid, ea, event.exit_code())
			elif eid == I.LIB_LOADED:
				hook.dbg_library_load(pid, tid, ea, info.name, info.base, info.size)
			elif eid == I.LIB_UNLOADED:
				hook.dbg_library_unload(pid, tid, ea, event.info())
			elif eid == I.INFORMATION:
				hook.dbg_information(pid, tid, ea, event.info())
			elif eid == I.EXCEPTION:
				# Observed: the notification has the code as a signed int, the event has it unsigned.
				code = event.exc().code
				hook.dbg_exception(pid, tid, ea, code - (1 << 32) if code & 0x80000000 else code, True, event.exc().ea, event.exc().info)
			elif eid == I.BREAKPOINT and event._run_to:
				hook.dbg_run_to(pid, tid, ea)
			elif eid == I.BREAKPOINT:
				hook.dbg_bpt(tid, ea)
		# Observed: IDA tells of every suspension, behind the event's own notification, unless a hook continued the process from inside that.
		if suspends and self.state == D.DSTATE_SUSP:
			for hook in list(self.hooks):
				hook.dbg_suspend_process()
		if eid in (I.PROCESS_EXITED, I.PROCESS_DETACHED):
			self.end()

	def wait_for_next_event(self, wfne, timeout):
		self.calls.append(('wait', wfne, timeout))
		if self.state == D.DSTATE_NOTASK:
			return D.DEC_NOTASK
		if wfne & D.WFNE_CONT:
			self.continue_process()
		if wfne & D.WFNE_NOWAIT:
			return D.DEC_TIMEOUT
		if self.state == D.DSTATE_SUSP and not self.requests:
			return D.DEC_TIMEOUT
		while True:
			event = self.next_event()
			if event is None:
				return D.DEC_TIMEOUT
			self.deliver(event)
			# A hook may have continued the process (request_continue_process, run_requests): then it goes on.
			if self.state != D.DSTATE_RUN or wfne & D.WFNE_ANY:
				return event.eid()

	def pump(self):
		''' Run the process the way IDA's own event loop does when the user resumes it from IDA: nobody waits, and hooks are the only ones to see the events. '''
		self.continue_process()
		while self.state == D.DSTATE_RUN:
			event = self.next_event()
			if event is None:
				return
			self.deliver(event)

	# THREADS AND REGISTERS
	def select_thread(self, tid):
		self.calls.append(('select_thread', tid))
		if self.state != D.DSTATE_SUSP or tid not in self.threads:
			return False
		self.current_tid = tid
		return True

	def get_reg(self, name, missing=Exception):
		thread = self.threads.get(self.current_tid)
		if self.state != D.DSTATE_SUSP or thread is None or name not in thread.regs:
			if missing is Exception:
				raise Exception('Failed to retrieve register value')
			return missing
		return thread.regs[name]

	def set_reg(self, name, value):
		thread = self.threads.get(self.current_tid)
		if self.state != D.DSTATE_SUSP or thread is None or name not in thread.regs:
			return False
		thread.regs[name] = value
		return True

	def collect_stack_trace(self, tid, trace):
		thread = self.threads.get(tid)
		if self.state != D.DSTATE_SUSP or thread is None or not thread.frames:
			return False
		for callea, funcea in thread.frames:
			frame = I.call_stack_info_t()
			frame.callea, frame.funcea, frame.funcok = callea, funcea, True
			trace.append(frame)
		return True

	# MEMORY
	def region(self, ea, size):
		for base, data in self.memory:
			if base <= ea and ea + size <= base + len(data):
				return base, data
		return None

	def read(self, ea, size):
		found = self.region(ea, size) if self.state != D.DSTATE_NOTASK else None
		if found is None:
			return None
		base, data = found
		return bytes(data[ea-base:ea-base+size])

	def write(self, ea, buffer):
		found = self.region(ea, len(buffer)) if self.state != D.DSTATE_NOTASK else None
		if found is None:
			return False
		base, data = found
		data[ea-base:ea-base+len(buffer)] = buffer
		return True

	# MODULES
	def module_after(self, base, modinfo):
		if not self.lists_modules:
			return False
		for name, start, size in sorted(self.modules, key=lambda m: m[1]):
			if base is None or start > base:
				modinfo.name, modinfo.base, modinfo.size = name, start, size
				return True
		return False

	# BREAKPOINTS
	def resolved(self, record):
		if record['kind'] == D.BPLT_ABS:
			return record['ea']
		# Observed: the path places the breakpoint when it is the module's full path as the debugger reports it, or only a file name, ignoring case. The same path spelled another way does not.
		path = record['path'].lower()
		for name, base, size in self.modules:
			name = name.lower()
			if path == name or (self.places_by_file_name and path == name.replace('\\', '/').rsplit('/', 1)[-1]):
				return base + record['offset']
		return BADADDR

	def bpt_at(self, ea):
		return next((b for b in self.bpts if self.resolved(b) == ea and ea != BADADDR), None)

	def bpt_by_loc(self, loc):
		for b in self.bpts:
			if b['kind'] != loc.type():
				continue
			if b['kind'] == D.BPLT_ABS and b['ea'] == loc.ea():
				return b
			if b['kind'] == D.BPLT_REL and b['path'] == loc.path() and b['offset'] == loc.offset():
				return b
		return None

	def fill_bpt(self, record, bpt):
		bpt.loc = D.bpt_location_t()
		if record['kind'] == D.BPLT_ABS:
			bpt.loc.set_abs_bpt(record['ea'])
		else:
			bpt.loc.set_rel_bpt(record['path'], record['offset'])
		bpt.ea, bpt.flags, bpt.type = self.resolved(record), record['flags'], 4
		return True

	def add_bpt(self, *args):
		if isinstance(args[0], D.bpt_t):
			loc = args[0].loc
			self.calls.append(('add_bpt', loc.type(), loc.path() or loc.ea(), loc.offset()))
			# Observed: adding a bpt_t that is already there reports success and adds nothing.
			if self.bpt_by_loc(loc) is None:
				self.bpts.append({ 'kind' : loc.type(), 'ea' : loc.ea(), 'path' : loc.path(), 'offset' : loc.offset(), 'flags' : args[0].flags })
			return True
		ea = args[0]
		self.calls.append(('add_bpt', D.BPLT_ABS, ea, 0))
		if any(b['kind'] == D.BPLT_ABS and b['ea'] == ea for b in self.bpts):
			return False
		self.bpts.append({ 'kind' : D.BPLT_ABS, 'ea' : ea, 'path' : '', 'offset' : 0, 'flags' : D.BPT_BRK | D.BPT_ENABLED })
		return True

	def del_bpt(self, where):
		record = self.bpt_by_loc(where) if isinstance(where, D.bpt_location_t) else self.bpt_at(where)
		if record is None:
			return False
		self.bpts.remove(record)
		return True

	def enable_bpt(self, where, enable):
		located = isinstance(where, D.bpt_location_t)
		record = self.bpt_by_loc(where) if located else self.bpt_at(where)
		if record is None:
			return False
		record['flags'] = record['flags'] | D.BPT_ENABLED if enable else record['flags'] & ~D.BPT_ENABLED
		# Observed on macOS: with a location, IDA 9.4 does it but returns False. On Windows it returns True.
		return not located

	# CALLS
	def appcall(self, ea, tif, args):
		self.calls.append(('appcall', ea, self.current_tid, args))
		if self.state != D.DSTATE_SUSP:
			raise Exception('Cannot call application without an active debugger')
		function = self.functions.get(ea)
		if function is None:
			raise Exception(f'Appcall: the process crashed at {hex(ea)}')
		return function(*args)

def database_memory() -> list:
	''' The open database's segments, as memory regions of the process. '''
	import idautils
	import ida_bytes
	from ida_scripts import compat
	regions = []
	for start in idautils.Segments():
		end = compat.segment_bounds(start)[1]
		regions.append([start, bytearray(ida_bytes.get_bytes(start, end - start) or b'')])
	return regions

def install(test, fake: FakeIDA) -> FakeIDA:
	''' Put the fake modules in place of `ida_dbg` and `ida_idd` inside ida_scripts for the length of `test`, backed by `fake`. Starts and ends with a fresh `dbg`. '''
	global current
	current = fake
	for name in ('compat', 'debugger', 'module'):
		module = sys.modules[f'ida_scripts.{name}']
		for attribute, replacement in (('ida_dbg', D), ('ida_idd', I)):
			if hasattr(module, attribute):
				patcher = mock.patch.object(module, attribute, replacement)
				patcher.start()
				test.addCleanup(patcher.stop)
	reset()
	# Cleanups run last first, so this runs while the fakes are still in place.
	test.addCleanup(reset)
	return fake

def reset():
	''' Unhook and forget everything `dbg` and `Module` keep. '''
	from ida_scripts import debugger, module
	debugger._unload()
	debugger.dbg.__init__()
	module.Module.static_bases.clear()
