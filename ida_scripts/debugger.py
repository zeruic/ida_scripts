''' Provides class(es) for driving the debugger: the process, breakpoints, registers and events.

Everything goes through the one `Debugger` instance, `dbg`, and the `Breakpoint` class:

```
dbg.start('/path/to/target')               # suspended at the process start
Breakpoint.add('main')
event = dbg.resume()                       # suspended at main, its thread selected
print(hex(dbg.reg('X0')), dbg.pc, dbg.stack())
Breakpoint.add(0x4de0, module='Engine.dll', handler=lambda e: print(dbg.reg('RCX')))
dbg.resume()                               # the handler returns None, so the process runs on
dbg.stop()
```

The calls wait for the process themselves, so they work the same in a headless script and inside IDA.
'''

import contextlib
import os
import time
import traceback
from typing import *

from . import compat
from .compat import IN_IDA
from .utils import *
from .memory import Pointer
from .module import Module, file_name, same_module

if TYPE_CHECKING:
	from .func import Func

if IN_IDA:
	import ida_dbg
	import ida_idd
	import ida_ida
	import ida_bytes
	import ida_kernwin

__all__ = ['Event', 'Debugger', 'dbg', 'Breakpoint']

KINDS = ('process_start', 'process_exit', 'library_load', 'library_unload', 'breakpoint', 'exception', 'thread_start', 'thread_exit', 'suspended', 'other')
''' The values of `Event.kind`. '''

SUSPENDING = ('process_start', 'breakpoint', 'exception', 'suspended')
''' The kinds of event that leave the process suspended. Others do too when IDA's debugger options say so. '''

SUSPEND_TIMEOUT = 5
''' Seconds `Debugger.suspend` and `Debugger.detach` wait for the process. '''

WAIT_SLICE = 0.5
''' Seconds one wait inside IDA lasts at most. Nothing reaches Python while IDA waits (not Ctrl-C, not the time limit of a host such as an MCP server), so a long wait is made of short ones. '''

EVENT_KINDS = {}
if IN_IDA:
	EVENT_KINDS = {
		ida_idd.PROCESS_STARTED : 'process_start',
		ida_idd.PROCESS_ATTACHED : 'process_start',
		ida_idd.PROCESS_EXITED : 'process_exit',
		ida_idd.PROCESS_DETACHED : 'process_exit',
		ida_idd.LIB_LOADED : 'library_load',
		ida_idd.LIB_UNLOADED : 'library_unload',
		ida_idd.BREAKPOINT : 'breakpoint',
		ida_idd.EXCEPTION : 'exception',
		ida_idd.THREAD_STARTED : 'thread_start',
		ida_idd.THREAD_EXITED : 'thread_exit',
		ida_idd.PROCESS_SUSPENDED : 'suspended',
		ida_idd.STEP : 'suspended',
	}

# The hooks are kept on ida_dbg, which outlives this module, so a reload or a fresh import finds the ones an earlier copy installed.
HOOKS_KEY = '_ida_scripts_debugger_hooks'

@auto_repr(['kind', 'pid', 'tid', 'address', 'module', 'code', 'info'])
class Event:
	''' Represent one event of the debugged process, such as a breakpoint hit or a library load. '''

	def __init__(self, kind: str, pid: int = 0, tid: int = 0, address: Optional[int] = None, module: Optional[str] = None, code: Optional[int] = None, info: str = ''):
		''' Init with the event's kind (one of `KINDS`) and what IDA reported with it. '''
		self.kind: str = kind
		''' `'process_start'`, `'process_exit'`, `'library_load'`, `'library_unload'`, `'breakpoint'`, `'exception'`, `'thread_start'`, `'thread_exit'`, `'suspended'` or `'other'`.

		Attaching is a `'process_start'` and detaching a `'process_exit'`, with `info` set to `'attached'` or `'detached'`. Arriving at the target of `Debugger.run_to` is a `'breakpoint'` with `info` set to `'run_to'`. A finished step is `'suspended'`.
		'''
		self.pid: int = pid
		''' The process id. '''
		self.tid: int = tid
		''' The thread the event happened in. '''
		self.address: Optional[Pointer] = Pointer(address) if address is not None and address != compat.BADADDR else None
		''' Where it happened, `None` when IDA gives no address. '''
		self.module: Optional[str] = module
		''' The module's path, for `'process_start'`, `'library_load'` and `'library_unload'`. '''
		self.code: Optional[int] = code
		''' The exit code (`'process_exit'`, `'thread_exit'`) or the exception code (`'exception'`). '''
		self.info: str = info or ''
		''' What else IDA said: the exception message, or the text of an `'other'` event. '''
		self._resume = False

	@property
	def suspends(self) -> bool:
		''' Whether this kind of event leaves the process suspended (see `SUSPENDING`). '''
		return self.kind in SUSPENDING

def event_from_ida(event: 'ida_idd.debug_event_t') -> Event:
	''' An `Event` from IDA's description of the current debugger event. '''
	eid = event.eid()
	module, code, info = None, None, ''
	if eid in (ida_idd.PROCESS_STARTED, ida_idd.PROCESS_ATTACHED, ida_idd.LIB_LOADED):
		module = event.modinfo().name
	elif eid in (ida_idd.PROCESS_EXITED, ida_idd.THREAD_EXITED):
		code = event.exit_code()
	elif eid == ida_idd.EXCEPTION:
		code, info = event.exc().code, event.exc().info
	elif eid in (ida_idd.LIB_UNLOADED, ida_idd.INFORMATION, ida_idd.THREAD_STARTED):
		info = event.info()
		if eid == ida_idd.LIB_UNLOADED:
			module = info
	if eid == ida_idd.PROCESS_ATTACHED:
		info = 'attached'
	elif eid == ida_idd.PROCESS_DETACHED:
		info = 'detached'
	return Event(EVENT_KINDS.get(eid, 'other'), event.pid, event.tid, event.ea, module, code, info)

def same_event(event: Event, kind: str, reported: 'ida_idd.debug_event_t') -> bool:
	''' Whether a recorded event is the one IDA describes. One wait ends with one such event, so the kind and the thread tell it. '''
	stops = ('breakpoint', 'suspended')
	if event.kind != kind and not (event.kind in stops and kind in stops):
		return False
	return kind == 'process_exit' or event.tid == reported.tid

def default_debugger() -> Optional[str]:
	''' IDA's local debugger for the database's file type: `'win32'`, `'linux'`, `'mac'` or `'arm_mac'`. `None` when there is none. '''
	filetype = ida_ida.inf_get_filetype()
	arm = ida_ida.inf_get_procname() == 'ARM'
	if filetype == ida_ida.f_MACHO:
		return 'arm_mac' if arm else 'mac'
	if arm:
		return None
	if filetype == ida_ida.f_PE:
		return 'win32'
	if filetype == ida_ida.f_ELF:
		return 'linux'
	return None

class BreakpointState:
	''' What `dbg` keeps about one breakpoint between hits: its handler and how often it was hit. '''

	def __init__(self):
		''' Init with no handler and no hits. '''
		self.handler: Optional[Callable[[Event], Any]] = None
		''' Called on each hit. '''
		self.hits: int = 0
		''' Hits so far. '''

@auto_repr(['state', 'event'])
class Debugger:
	''' Drive IDA's debugger. There is one instance, `dbg`.

	A process is started with `Debugger.start` or `Debugger.attach`, and then runs only when asked: `Debugger.resume`, `Debugger.run_to` and `Debugger.wait` return once it is suspended again (or gone), with the event that stopped it. Registers, `Debugger.pc`, `Debugger.sp` and `Debugger.stack` belong to the thread of that event unless `Debugger.thread` was changed since.

	From the first use on, every event is recorded in `Debugger.events`, and `Debugger.modules` follows the loaded modules. Handlers can be attached to events with `Debugger.on` and to breakpoints with `Breakpoint.add`.

	Everything that needs a process raises `DebuggerError` when there is none, or when it is running and has to be suspended.
	'''

	def __init__(self):
		''' Init with nothing recorded. The hooks are installed on first use. '''
		self.events: List[Event] = []
		''' Every event since the first use (or `Debugger.clear_events`), oldest first. '''
		self.event: Optional[Event] = None
		''' The latest event. '''
		self.handler_error: Optional[BaseException] = None
		''' The exception the last failing handler raised. Cleared when `Debugger.resume`, `Debugger.wait` or the like starts waiting. '''
		self._hooks = None
		self._handlers: Dict[str, List[Callable[[Event], Any]]] = {}
		self._breakpoints: Dict[tuple, BreakpointState] = {}
		self._modules: Dict[int, Module] = {}
		self._thread: Optional[int] = None
		self._waiting = False
		self._since: List[Event] = []

	# STATE
	@property
	def state(self) -> str:
		''' `'none'` (no process), `'running'` or `'suspended'`. '''
		if not IN_IDA:
			return 'none'
		self._ensure()
		state = ida_dbg.get_process_state()
		if state == ida_dbg.DSTATE_NOTASK:
			return 'none'
		return 'suspended' if state == ida_dbg.DSTATE_SUSP else 'running'

	@property
	def modules(self) -> List[Module]:
		''' The modules of the process, by address, as the load and unload events reported them. '''
		self._ensure()
		return sorted(self._modules.values(), key=lambda m: m.addr)

	@property
	def threads(self) -> List[int]:
		''' Ids of the process's threads. `[]` when there is no process. '''
		self._ensure()
		if not compat.debugger_active():
			return []
		return [ida_dbg.getn_thread(n) for n in range(ida_dbg.get_thread_qty())]

	@property
	def thread(self) -> int:
		''' The thread that registers are read from: the thread of the latest event, unless another one was assigned since. Assign a thread id to select it. '''
		self._ensure()
		if self._thread is not None and self._thread in self.threads:
			return self._thread
		return ida_dbg.get_current_thread()

	@thread.setter
	def thread(self, tid: int):
		self._need_suspended(f'selecting thread {tid}')
		if tid not in self.threads or not ida_dbg.select_thread(tid):
			raise DebuggerError(f'cannot select thread {tid}: the process has threads {self.threads}')
		self._thread = tid

	@property
	def pc(self) -> Pointer:
		''' The program counter of `Debugger.thread`. '''
		self._need_suspended('reading the program counter')
		self._select()
		value = ida_dbg.get_ip_val()
		if value is None:
			raise DebuggerError(f'cannot read the program counter of thread {self.thread}')
		return Pointer(value)

	@property
	def sp(self) -> Pointer:
		''' The stack pointer of `Debugger.thread`. '''
		self._need_suspended('reading the stack pointer')
		self._select()
		value = ida_dbg.get_sp_val()
		if value is None:
			raise DebuggerError(f'cannot read the stack pointer of thread {self.thread}')
		return Pointer(value)

	# PROCESS
	def start(self, path: str, args: str = '', cwd: str = None, debugger: str = None, timeout: float = 10) -> Event:
		''' Start a process under the debugger and wait until it is suspended at its start.

		Dialogs that would block a headless run are turned off while it starts. If the start fails, no process is left behind.

		Parameters
		----------
		path : str
			The executable.
		args : str, default = ''
			Its command line arguments, quoted as on a command line.
		cwd : str, default = None
			Its working directory. `None` is the executable's folder.
		debugger : str, default = None
			IDA's name of the debugger module, such as `'win32'`, `'linux'`, `'mac'` or `'arm_mac'`. `None` keeps the one the database has, or picks the local debugger for the database's file type.
		timeout : float, default = 10
			Seconds to wait for the process to be suspended.

		Returns
		-------
		`Event`
			The `'process_start'` event.

		Raises
		------
		DebuggerError
			When a process is already being debugged, the debugger cannot be loaded, or the process cannot be started.
		'''
		self._ensure()
		action = f'starting {path}'
		if compat.debugger_active():
			raise DebuggerError(f'{action}: a process is already being debugged, stop it first')
		path = os.path.abspath(path)
		if not os.path.isfile(path):
			raise DebuggerError(f'{action}: there is no such file')
		self._load(debugger, action)
		self._modules.clear()
		with self._headless(ida_dbg.DOPT_START_BPT):
			code = ida_dbg.start_process(path, args or '', cwd or os.path.dirname(path))
			if code != 1:
				reason = 'IDA did not start it (start_process returned 0, a cancelled start, and IDA\'s output says why)' if code == 0 else f'the debugger could not create the process (start_process returned {code})'
				raise DebuggerError(f'{action}: {reason}{self._abandon()}')
			try:
				event = self._wait(action, timeout)
			except DebuggerError as error:
				raise DebuggerError(f'{error}{self._abandon()}') from None
		if event.kind == 'process_exit':
			raise DebuggerError(f'{action}: the process exited at once, with code {event.code}')
		return event

	def attach(self, pid: int, debugger: str = None, timeout: float = 10) -> Event:
		''' Attach to a running process and wait until it is suspended.

		Parameters
		----------
		pid : int
			The process id.
		debugger : str, default = None
			As for `Debugger.start`.
		timeout : float, default = 10
			Seconds to wait for the process to be suspended.

		Returns
		-------
		`Event`
			A `'process_start'` event with `info` `'attached'`.
		'''
		self._ensure()
		action = f'attaching to process {pid}'
		if compat.debugger_active():
			raise DebuggerError(f'{action}: a process is already being debugged, stop or detach it first')
		self._load(debugger, action)
		self._modules.clear()
		with self._headless():
			code = ida_dbg.attach_process(pid, -1)
			if code != 1:
				reasons = { 0 : 'IDA did not attach (attach_process returned 0, a cancelled attach, and IDA\'s output says why)', -1 : 'the debugger could not attach (there is no such process, or permission is missing)', -2 : 'there is no compatible process with that id', -3 : 'this debugger cannot attach', -4 : 'the debugger is not initialised' }
				raise DebuggerError(f'{action}: {reasons.get(code, f"attach_process returned {code}")}{self._abandon()}')
			try:
				event = self._wait(action, timeout)
			except DebuggerError as error:
				raise DebuggerError(f'{error}{self._abandon()}') from None
		# No load events come for the modules that were loaded before.
		for module in Module._listed():
			self._modules.setdefault(module.addr, module)
		return event

	def wait(self, timeout: float = None) -> Event:
		''' Wait until the running process is suspended or exits, and return the event. Returns the latest event at once when the process is suspended already.

		Breakpoint handlers that return something falsy let the process run on, as in `Debugger.resume`.

		Raises `DebuggerError` when there is no process, or when it is still running after `timeout` seconds (`None` waits as long as it takes).
		'''
		self._ensure()
		state = self.state
		if state == 'none':
			raise DebuggerError('waiting: no process is being debugged')
		if state == 'suspended':
			return self.event or self._current_event()
		return self._wait('waiting', timeout)

	def resume(self, timeout: float = None) -> Optional[Event]:
		''' Continue the suspended process and wait until it is suspended again or exits.

		Breakpoints whose handler returns something falsy do not stop the wait: the process runs on through them.

		Parameters
		----------
		timeout : float, default = None
			Seconds to wait. `None` waits as long as it takes. `0` returns at once, with `None`, and leaves the process running (`Debugger.wait` gets the event later).

		Returns
		-------
		`Event`
			The event that suspended the process (its thread is now selected), or the `'process_exit'` event.

		Raises
		------
		DebuggerError
			When the process is not suspended, or still running after `timeout` seconds.
		'''
		self._need_suspended('resuming')
		if timeout == 0:
			ida_dbg.wait_for_next_event(ida_dbg.WFNE_CONT | ida_dbg.WFNE_NOWAIT | ida_dbg.WFNE_SILENT, 0)
			return None
		return self._wait('resuming', timeout, ida_dbg.WFNE_CONT)

	def run_to(self, target: Union[int, str, Pointer], timeout: float = None) -> Event:
		''' Continue the suspended process until it reaches `target`, and return the event.

		It stops earlier at a breakpoint whose handler (if any) wants it to stop. Raises `DebuggerError` as `Debugger.resume` does.
		'''
		ea = to_ea(target)
		action = f'running to {hex(ea)}'
		self._need_suspended(action)
		if not ida_dbg.run_to(ea):
			raise DebuggerError(f'{action}: IDA refused')
		return self._wait(action, timeout)

	def suspend(self) -> bool:
		''' Suspend the running process. Returns whether it is suspended. Raises `DebuggerError` when there is no process. '''
		state = self.state
		if state == 'none':
			raise DebuggerError('suspending: no process is being debugged')
		if state == 'suspended':
			return True
		if not ida_dbg.suspend_process():
			return False
		try:
			self._wait('suspending', SUSPEND_TIMEOUT, follow=False)
		except DebuggerError:
			return False
		return self.state == 'suspended'

	def stop(self, timeout: float = 5) -> bool:
		''' Terminate the process. Returns `False` when there was none, `True` once it is gone.

		Raises `DebuggerError` when it is still there after `timeout` seconds.
		'''
		if self.state == 'none':
			return False
		ida_dbg.exit_process()
		return self._wait_gone('stopping the process', timeout)

	def detach(self) -> bool:
		''' Detach from the process and let it run on. Returns whether the debugger let go of it. Raises `DebuggerError` when there is no process. '''
		if self.state == 'none':
			raise DebuggerError('detaching: no process is being debugged')
		if not ida_dbg.detach_process():
			return False
		try:
			return self._wait_gone('detaching', SUSPEND_TIMEOUT)
		except DebuggerError:
			return False

	# REGISTERS
	def reg(self, name: str, value: int = None) -> Union[int, float, bytes, bool]:
		''' Read/Write a register of `Debugger.thread`.

		Reads return what IDA gives for the register: an `int` for integer registers. Writes return whether they succeeded.
		'''
		action = f'reading register {name}' if value is None else f'writing register {name}'
		self._need_suspended(action)
		self._select()
		try:
			if value is None:
				return ida_dbg.get_reg_val(name)
			return bool(ida_dbg.set_reg_val(name, value))
		except Exception as error:
			raise DebuggerError(f'{action} of thread {self.thread}: {error}') from None

	def regs(self, *names: str) -> Dict[str, int]:
		''' Read several registers of `Debugger.thread` at once. Without names, every integer register the debugger can read. '''
		self._need_suspended('reading registers')
		if names:
			return { name : self.reg(name) for name in names }
		values = {}
		for info in ida_idd.dbg_get_registers() or ():
			if ida_dbg.is_reg_integer(info[0]):
				with contextlib.suppress(DebuggerError):
					values[info[0]] = self.reg(info[0])
		return values

	def stack(self, depth: int = 16) -> List[Pointer]:
		''' The call stack of `Debugger.thread`, innermost first: the current address, then the call site in each caller. At most `depth` entries. '''
		self._need_suspended('reading the call stack')
		tid = self.thread
		self._select()
		trace = ida_idd.call_stack_t()
		if not ida_dbg.collect_stack_trace(tid, trace):
			raise DebuggerError(f'cannot collect the call stack of thread {tid}')
		return [Pointer(frame.callea) for frame in trace][:depth]

	# CALLS
	def call(self, target: Union[int, str, Pointer, 'Func'], prototype: str, *args) -> Any:
		''' Call a function in the suspended process, on `Debugger.thread`, and return its result.

		Parameters
		----------
		target : int, str, `Pointer` or `Func`
			The function.
		prototype : str
			Its C declaration, such as `'int add(int a, int b)'`.
		*args
			The arguments. Python ints and strings convert by themselves, see `Debugger.ref` and `Debugger.wide` for the others.

		Returns
		-------
		The function's result, converted by IDA's Appcall.
		'''
		ea = to_ea(target)
		action = f'calling {hex(ea)}'
		self._need_suspended(action)
		if not ida_bytes.is_mapped(ea):
			raise DebuggerError(f'{action}: the address is not mapped')
		declaration = prototype.strip()
		if not declaration.endswith(';'):
			declaration += ';'
		try:
			function = ida_idd.Appcall.proto(ea, declaration)
		except Exception as error:
			raise DebuggerError(f'{action} as {prototype!r}: {error}') from None
		self._select()
		# Appcall runs the process itself: handlers must not continue it behind Appcall's back.
		self._waiting = True
		try:
			return function(*args)
		except Exception as error:
			raise DebuggerError(f'{action} failed: {error}') from None
		finally:
			self._waiting = False

	def ref(self, value: Any = 0) -> Any:
		''' A by-reference argument for `Debugger.call`: the callee gets a pointer to a copy of `value`. Read `.value` afterwards for what it wrote there. '''
		return ida_idd.Appcall.byref(value)

	def wide(self, text: str) -> bytes:
		''' A UTF-16 string argument for `Debugger.call`, with its terminator. '''
		return ida_idd.Appcall.unicode(text + '\0')

	# EVENTS
	def on(self, kind: str, handler: Callable[[Event], Any]):
		''' Call `handler(event)` for every event of this kind (one of `KINDS`). The return value is ignored. An exception goes to `Debugger.handler_error` and keeps the process suspended. '''
		self._ensure()
		if kind not in KINDS:
			raise ValueError(f'unknown event kind {kind!r}, use one of {", ".join(KINDS)}')
		self._handlers.setdefault(kind, []).append(handler)

	def off(self, kind: str, handler: Callable = None):
		''' Remove a handler given to `Debugger.on`, or every handler of this kind when `handler` is `None`. '''
		if handler is None:
			self._handlers.pop(kind, None)
		elif handler in self._handlers.get(kind, []):
			self._handlers[kind].remove(handler)

	def clear_events(self):
		''' Forget the recorded events. `Debugger.event` stays. '''
		self.events.clear()

	# INTERNAL
	def _ensure(self):
		if self._hooks is None and IN_IDA:
			self._hooks = install_hooks(self)
			for module in Module._listed():
				self._modules[module.addr] = module

	def _need_suspended(self, action: str):
		state = self.state
		if state != 'suspended':
			raise DebuggerError(f'{action}: ' + ('no process is being debugged' if state == 'none' else 'the process is running, suspend it first'))

	def _select(self):
		if self._thread is not None and self._thread != ida_dbg.get_current_thread() and self._thread in self.threads:
			ida_dbg.select_thread(self._thread)

	def _load(self, name: Optional[str], action: str):
		if name is None:
			if ida_dbg.dbg_is_loaded():
				return
			name = default_debugger()
			if name is None:
				raise DebuggerError(f'{action}: IDA has no local debugger for this database, pass debugger=')
		if ida_dbg.dbg_is_loaded() and ida_idd.dbg_get_name() == name:
			return
		if not ida_dbg.load_debugger(name, False):
			raise DebuggerError(f'{action}: IDA cannot load its local {name!r} debugger')

	@contextlib.contextmanager
	def _headless(self, options: int = 0):
		old = ida_dbg.set_debugger_options(0)
		ida_dbg.set_debugger_options((old & ~ida_dbg.DOPT_EXCDLG) | ida_dbg.EXCDLG_NEVER | options)
		batch = ida_kernwin.cvar.batch
		ida_kernwin.cvar.batch = 1
		try:
			yield
		finally:
			ida_kernwin.cvar.batch = batch
			ida_dbg.set_debugger_options(old)

	def _abandon(self) -> str:
		''' Stop what a failed start or attach left behind. Returns a note for the error message when that failed too. '''
		if not compat.debugger_active():
			return ''
		try:
			self.stop()
			return ''
		except DebuggerError as error:
			return f' ({error})'

	def _wait(self, action: str, timeout: Optional[float], flags: int = 0, follow: bool = True) -> Event:
		''' Wait until the process is suspended or gone, continuing past breakpoints whose handlers asked for it. '''
		deadline = None if timeout is None else time.monotonic() + timeout
		self.handler_error = None
		self._waiting = True
		try:
			self._since = []
			while True:
				extra, wait_for = wait_time(deadline)
				code = ida_dbg.wait_for_next_event(flags | extra | ida_dbg.WFNE_SUSP | ida_dbg.WFNE_SILENT, wait_for)
				if code == ida_dbg.DEC_TIMEOUT:
					if compat.debugger_suspended():
						event = self.event or self._current_event()
						break
					if deadline is not None and time.monotonic() >= deadline:
						raise DebuggerError(f'{action}: the process is still running after {timeout} s')
					# Only a slice of the wait is over (see WAIT_SLICE). The process runs, so the next slice has nothing to continue.
					flags &= ~ida_dbg.WFNE_CONT
					continue
				if code == ida_dbg.DEC_NOTASK:
					event = next((e for e in reversed(self._since) if e.kind == 'process_exit'), None)
					if event is None:
						raise DebuggerError(f'{action}: no process is being debugged')
					break
				if code == ida_dbg.DEC_ERROR:
					raise DebuggerError(f'{action}: the debugger reported an error')
				event = self._current_event()
				if not (follow and event._resume and compat.debugger_suspended()):
					break
				if deadline is not None and time.monotonic() >= deadline:
					ida_dbg.wait_for_next_event(ida_dbg.WFNE_CONT | ida_dbg.WFNE_NOWAIT | ida_dbg.WFNE_SILENT, 0)
					raise DebuggerError(f'{action}: the process is still running after {timeout} s (breakpoint handlers kept it going)')
				flags = ida_dbg.WFNE_CONT
				self._since = []
		finally:
			self._waiting = False
		if event.kind != 'process_exit' and compat.debugger_suspended():
			self._thread = event.tid if event.tid in self.threads else None
			self._select()
		return event

	def _wait_gone(self, action: str, timeout: float) -> bool:
		''' Wait until the process is gone after an exit or detach request. '''
		deadline = time.monotonic() + timeout
		self._waiting = True
		try:
			while compat.debugger_active():
				if time.monotonic() >= deadline:
					raise DebuggerError(f'{action}: the process is still there after {timeout} s')
				extra, wait_for = wait_time(deadline)
				if ida_dbg.wait_for_next_event(extra | ida_dbg.WFNE_ANY | ida_dbg.WFNE_SILENT, wait_for) == ida_dbg.DEC_NOTASK:
					break
		finally:
			self._waiting = False
		self._thread = None
		return True

	def _current_event(self) -> Event:
		''' The recorded event that IDA reports as the current one, recorded now if the hooks missed it. '''
		current = ida_dbg.get_debug_event()
		if current is None or current.eid() == ida_idd.NO_EVENT:
			return self.event or Event('other')
		kind = EVENT_KINDS.get(current.eid(), 'other')
		for event in reversed(self._since):
			if same_event(event, kind, current):
				return event
		event = event_from_ida(current)
		self._record(event, hit=kind == 'breakpoint')
		return event

	def _record(self, event: Event, base: int = None, size: int = 0, hit: bool = False):
		''' Record an event, keep the module list current, and call the breakpoint's handler (for a `hit`) and the `Debugger.on` handlers. '''
		self.events.append(event)
		self._since.append(event)
		self.event = event
		if event.suspends:
			self._thread = event.tid
		if event.kind in ('process_start', 'library_load') and event.module and base is not None:
			self._modules[base] = Module(event.module, base, size)
			move_pending_breakpoints(event.module)
		elif event.kind == 'library_unload':
			for addr, module in list(self._modules.items()):
				if same_module(module.name, event.module or '') or (event.address is not None and addr == event.address.addr):
					del self._modules[addr]
		elif event.kind == 'process_exit':
			self._modules.clear()
		if hit:
			self._breakpoint_hit(event)
		for handler in list(self._handlers.get(event.kind, [])):
			self._call(handler, event)
		if event._resume and not self._waiting:
			# Nobody of ours is waiting (the user resumed the process from IDA, say), so the handler's wish to go on is passed to IDA directly.
			ida_dbg.request_continue_process()
			ida_dbg.run_requests()

	def _breakpoint_hit(self, event: Event):
		''' Count the hit and ask the breakpoint's handler whether the process goes on. '''
		state = self._breakpoints.setdefault(breakpoint_key_at(event.address.addr if event.address else compat.BADADDR), BreakpointState())
		state.hits += 1
		if state.handler is not None:
			event._resume = not self._call(state.handler, event)

	def _call(self, handler: Callable[[Event], Any], event: Event) -> Any:
		''' Call a handler. A failure is kept in `handler_error`, printed, and keeps the process suspended. '''
		try:
			return handler(event)
		except Exception as error:
			self.handler_error = error
			event._resume = False
			print(f'ida_scripts: the handler {getattr(handler, "__name__", handler)} failed on {event}:')
			traceback.print_exc()
			return True

def wait_time(deadline: Optional[float]) -> Tuple[int, int]:
	''' The extra `WFNE_` flag and the timeout for one `wait_for_next_event` call: a slice of a wait that ends by `deadline` (`None`: no limit), `WAIT_SLICE` seconds at most. '''
	remaining = WAIT_SLICE if deadline is None else min(WAIT_SLICE, max(0.0, deadline - time.monotonic()))
	return ida_dbg.WFNE_USEC, int(remaining * 1000000)

def install_hooks(debugger: Debugger) -> 'ida_dbg.DBG_Hooks':
	''' Hook IDA's debugger notifications to record events into `debugger`, replacing hooks an earlier copy of this module installed. '''

	class Hooks(ida_dbg.DBG_Hooks):

		told = None

		def record(self, kind: str, pid: int, tid: int, ea: int, module: str = None, code: int = None, info: str = '', base: int = None, size: int = 0) -> Event:
			event = Event(kind, pid, tid, ea, module, code, info)
			self.told = event
			try:
				debugger._record(event, base, size, hit=kind == 'breakpoint' and info != 'run_to')
			except Exception:
				print(f'ida_scripts: recording {event} failed:')
				traceback.print_exc()
			return event

		def current(self) -> Tuple[int, int, int]:
			''' pid, tid and address of IDA's current event, for the notifications that do not pass them. '''
			event = ida_dbg.get_debug_event()
			if event is None:
				return 0, ida_dbg.get_current_thread(), compat.BADADDR
			return event.pid, event.tid, event.ea

		def dbg_process_start(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
			self.record('process_start', pid, tid, ea, modinfo_name, base=modinfo_base, size=modinfo_size)

		def dbg_process_attach(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
			self.record('process_start', pid, tid, ea, modinfo_name, info='attached', base=modinfo_base, size=modinfo_size)

		def dbg_process_exit(self, pid, tid, ea, exit_code):
			self.record('process_exit', pid, tid, ea, code=exit_code)

		def dbg_process_detach(self, pid, tid, ea):
			# The win32 debugger reports the detach without a process: pid -1.
			if pid <= 0 and debugger.event is not None:
				pid = debugger.event.pid
			self.record('process_exit', pid, tid, ea, info='detached')

		def dbg_thread_start(self, pid, tid, ea):
			self.record('thread_start', pid, tid, ea)

		def dbg_thread_exit(self, pid, tid, ea, exit_code):
			self.record('thread_exit', pid, tid, ea, code=exit_code)

		def dbg_library_load(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
			self.record('library_load', pid, tid, ea, modinfo_name, base=modinfo_base, size=modinfo_size)

		def dbg_library_unload(self, pid, tid, ea, info):
			self.record('library_unload', pid, tid, ea, info, info=info)

		def dbg_information(self, pid, tid, ea, info):
			self.record('other', pid, tid, ea, info=info)

		def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
			# The code arrives as a signed int: 0xC0000005 as -1073741819.
			self.record('exception', pid, tid, ea, code=exc_code & 0xFFFFFFFF, info=exc_info)
			return 0

		def dbg_suspend_process(self):
			# IDA sends this behind the notification of every event that suspends the process (a breakpoint, the process start). It is an event of its own only when nothing else told of the suspension.
			told, self.told = self.told, None
			reported = ida_dbg.get_debug_event()
			if told is not None and reported is not None and told.kind == EVENT_KINDS.get(reported.eid()) and told.tid == reported.tid:
				return
			self.record('suspended', *self.current())
			self.told = None

		def dbg_bpt(self, tid, bptea):
			self.record('breakpoint', self.current()[0], tid, bptea)
			return 0

		def dbg_run_to(self, pid, tid, ea):
			self.record('breakpoint', pid, tid, ea, info='run_to')

		def dbg_step_into(self):
			self.record('suspended', *self.current(), info='step_into')

		def dbg_step_over(self):
			self.record('suspended', *self.current(), info='step_over')

		def dbg_step_until_ret(self):
			self.record('suspended', *self.current(), info='step_until_ret')

		def dbg_request_error(self, failed_command, failed_dbg_notification):
			self.record('other', *self.current(), info=f'request {failed_command} failed (notification {failed_dbg_notification})')

	remove_hooks()
	hooks = Hooks()
	if not hooks.hook():
		raise DebuggerError('cannot hook the debugger notifications')
	setattr(ida_dbg, HOOKS_KEY, hooks)
	return hooks

def remove_hooks():
	''' Unhook what this module (this copy or an earlier one) hooked. '''
	hooks = getattr(ida_dbg, HOOKS_KEY, None)
	if hooks is not None:
		hooks.unhook()
		setattr(ida_dbg, HOOKS_KEY, None)

dbg: Debugger = Debugger()
''' The debugger. '''

def _unload():
	''' Let go of IDA's debugger notifications. `load.py` calls this before it reloads the package. '''
	if IN_IDA:
		remove_hooks()
	dbg._hooks = None

if IN_IDA:
	remove_hooks()

# BREAKPOINTS

def ida_breakpoints() -> Iterator['ida_dbg.bpt_t']:
	''' Every breakpoint IDA has, as `bpt_t` copies. '''
	for n in range(ida_dbg.get_bpt_qty()):
		bpt = ida_dbg.bpt_t()
		if ida_dbg.getn_bpt(n, bpt):
			yield bpt

def breakpoint_key(bpt: 'ida_dbg.bpt_t') -> tuple:
	''' What identifies a breakpoint across hits, reloads and moves: its kind of location and the location. '''
	loc = bpt.loc
	kind = loc.type()
	if kind == ida_dbg.BPLT_ABS:
		return ('abs', loc.ea())
	if kind == ida_dbg.BPLT_REL:
		return ('rel', file_name(loc.path()).lower(), loc.offset())
	if kind == ida_dbg.BPLT_SYM:
		return ('sym', loc.symbol(), loc.offset())
	return ('src', loc.path(), loc.lineno())

def breakpoint_key_at(ea: int) -> tuple:
	''' The key of the breakpoint at `ea`. '''
	bpt = ida_dbg.bpt_t()
	return breakpoint_key(bpt) if ida_dbg.get_bpt(ea, bpt) else ('abs', ea)

def move_pending_breakpoints(path: str):
	''' Give the full path of a module that just loaded to its module-relative breakpoints that only have its file name, so IDA places them. '''
	for bpt in list(ida_breakpoints()):
		loc = bpt.loc
		if loc.type() != ida_dbg.BPLT_REL or bpt.ea != compat.BADADDR or loc.path() == path or not same_module(path, loc.path()):
			continue
		enabled, offset = bpt.enabled(), loc.offset()
		ida_dbg.del_bpt(loc)
		moved = ida_dbg.bpt_t()
		moved.set_rel_bpt(path, offset)
		ida_dbg.add_bpt(moved)
		if not enabled:
			ida_dbg.enable_bpt(moved.loc, False)

@auto_repr(['address', 'module', 'offset', 'enabled', 'hits'])
class Breakpoint:
	''' Represent a breakpoint: at an address, or at an offset into a module (which may not be loaded yet).

	```
	Breakpoint.add('main')
	Breakpoint.add(0x4de0, module='Engine.dll', handler=lambda event: print(dbg.regs('RCX', 'RDX')))
	```

	A handler is called as `handler(event)` on each hit, with the process suspended. When it returns something falsy the process goes on by itself (tracing). When it returns something truthy the process stays suspended and `Debugger.resume` returns the event. Without a handler the process stays suspended.

	The breakpoints are IDA's: they show in IDA's list, and `Breakpoint.all` lists the ones set there too.
	'''

	def __init__(self, bpt: 'ida_dbg.bpt_t'):
		''' Init from IDA's description of the breakpoint. '''
		self.key: tuple = breakpoint_key(bpt)
		''' What identifies the breakpoint: `('abs', address)`, `('rel', module file name, offset)`, `('sym', symbol, offset)` or `('src', file, line)`. '''
		self._module: Optional[str] = bpt.loc.path() if self.key[0] == 'rel' else None

	@staticmethod
	def add(target: Union[int, str, Pointer, 'Func'], module: str = None, handler: Callable[[Event], Any] = None) -> 'Breakpoint':
		''' Add a breakpoint, or return the one already there.

		Parameters
		----------
		target : int, str, `Pointer` or `Func`
			The address. With `module`, the offset into the module.
		module : str, default = None
			A module's file name or full path, such as `'Engine.dll'`. The module does not have to be loaded yet: the breakpoint is placed when it loads.
		handler : callable, default = None
			Called on each hit as `handler(event)`. See `Breakpoint`. Replaces the handler of a breakpoint that is already there.

		Returns
		-------
		`Breakpoint`

		Raises
		------
		DebuggerError
			When IDA refuses the breakpoint.
		'''
		dbg._ensure()
		if module is None:
			ea = to_ea(target)
			if not ida_dbg.exist_bpt(ea) and not ida_dbg.add_bpt(ea, 0, ida_idd.BPT_DEFAULT):
				raise DebuggerError(f'cannot add a breakpoint at {hex(ea)}')
			breakpoint = Breakpoint.find(ea)
			where = hex(ea)
		else:
			offset = to_ea(target)
			where = f'{module}+{hex(offset)}'
			if Breakpoint.find(offset, module) is None:
				loaded = Module.find(module)
				bpt = ida_dbg.bpt_t()
				bpt.set_rel_bpt(loaded.name if loaded else module, offset)
				ida_dbg.add_bpt(bpt)
			breakpoint = Breakpoint.find(offset, module)
		if breakpoint is None:
			raise DebuggerError(f'cannot add a breakpoint at {where}')
		if handler is not None:
			breakpoint.handler = handler
		return breakpoint

	@staticmethod
	def find(target: Union[int, str, Pointer, 'Func'], module: str = None) -> Optional['Breakpoint']:
		''' The breakpoint at an address, or at an offset into a module (by file name or full path, ignoring case). `None` when there is none. '''
		dbg._ensure()
		if module is None:
			bpt = ida_dbg.bpt_t()
			return Breakpoint(bpt) if ida_dbg.get_bpt(to_ea(target), bpt) else None
		offset = to_ea(target)
		for bpt in ida_breakpoints():
			if bpt.loc.type() == ida_dbg.BPLT_REL and bpt.loc.offset() == offset and same_module(bpt.loc.path(), module):
				return Breakpoint(bpt)
		return None

	@staticmethod
	def all() -> List['Breakpoint']:
		''' Every breakpoint IDA has. '''
		dbg._ensure()
		return [Breakpoint(bpt) for bpt in ida_breakpoints()]

	@staticmethod
	def clear() -> int:
		''' Remove every breakpoint. Returns how many were removed. '''
		return sum(1 for breakpoint in Breakpoint.all() if breakpoint.remove())

	def bpt(self) -> Optional['ida_dbg.bpt_t']:
		''' IDA's current description of this breakpoint, `None` when it was removed. '''
		return next((bpt for bpt in ida_breakpoints() if breakpoint_key(bpt) == self.key), None)

	def remove(self) -> bool:
		''' Remove the breakpoint. Returns whether it was there. '''
		bpt = self.bpt()
		dbg._breakpoints.pop(self.key, None)
		return bool(bpt) and bool(ida_dbg.del_bpt(bpt.loc))

	@property
	def enabled(self) -> bool:
		''' Whether the breakpoint is enabled. Assign to enable or disable it. '''
		bpt = self.bpt()
		return bool(bpt) and bool(bpt.enabled())

	@enabled.setter
	def enabled(self, value: bool):
		bpt = self.bpt()
		if bpt is None:
			raise DebuggerError(f'cannot {"enable" if value else "disable"} {self}: it was removed')
		# The return value is no use: IDA 9.4 reports failure for a location even when it did it.
		ida_dbg.enable_bpt(bpt.loc, bool(value))
		if self.enabled != bool(value):
			raise DebuggerError(f'cannot {"enable" if value else "disable"} {self}')

	@property
	def address(self) -> Optional[Pointer]:
		''' Where the breakpoint is in the process. `None` while its module is not loaded, or once it is removed. '''
		bpt = self.bpt()
		return Pointer(bpt.ea) if bpt and bpt.ea != compat.BADADDR else None

	@property
	def module(self) -> Optional[str]:
		''' The module of a module-relative breakpoint, as IDA has it: the name it was added with, or the module's full path when IDA could only place it by that. `None` for any other breakpoint. '''
		bpt = self.bpt()
		if bpt is not None and bpt.loc.type() == ida_dbg.BPLT_REL:
			return bpt.loc.path()
		return self._module

	@property
	def offset(self) -> Optional[int]:
		''' The offset into the module of a module-relative breakpoint. `None` for any other breakpoint. '''
		return self.key[2] if self.key[0] == 'rel' else None

	@property
	def hits(self) -> int:
		''' How often the breakpoint was hit since the first use of `dbg`. '''
		state = dbg._breakpoints.get(self.key)
		return state.hits if state else 0

	@property
	def handler(self) -> Optional[Callable[[Event], Any]]:
		''' The function called on each hit, see `Breakpoint`. Assign to change it, `None` to remove it. '''
		state = dbg._breakpoints.get(self.key)
		return state.handler if state else None

	@handler.setter
	def handler(self, handler: Optional[Callable[[Event], Any]]):
		dbg._breakpoints.setdefault(self.key, BreakpointState()).handler = handler

	def __hash__(self) -> int:
		return hash(self.key)

	def __eq__(self, other: object) -> bool:
		return type(other) is Breakpoint and self.key == other.key

	def __hash__(self) -> int:
		return hash(self.key)
