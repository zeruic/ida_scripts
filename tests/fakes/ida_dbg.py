''' Fake `ida_dbg`: the subset of IDA 9.4's names that ida_scripts uses, with the same parameters, run against `process.current`. '''

from . import process as _process

# Values as in IDA 9.4, checked against the real module by tests/test_debugger.py.
DSTATE_SUSP = -1
DSTATE_NOTASK = 0
DSTATE_RUN = 1
DEC_NOTASK = -2
DEC_ERROR = -1
DEC_TIMEOUT = 0
WFNE_ANY = 1
WFNE_SUSP = 2
WFNE_SILENT = 4
WFNE_CONT = 8
WFNE_NOWAIT = 16
WFNE_USEC = 32
DOPT_START_BPT = 0x2
DOPT_LIB_BPT = 0x80
DOPT_EXCDLG = 0x6000
EXCDLG_NEVER = 0
EXCDLG_ALWAYS = 0x6000
BPLT_ABS = 0
BPLT_REL = 1
BPLT_SYM = 2
BPLT_SRC = 3
BPT_BRK = 1
BPT_ENABLED = 8

def _ida():
	return _process.current

class DBG_Hooks(object):
	''' Notifications of the debugger. Hooked instances get the simulated process's events. '''

	def __init__(self, _flags: int=0, _hkcb_flags: int=1):
		pass

	def hook(self) ->bool:
		if self in _ida().hooks:
			return False
		_ida().hooks.append(self)
		return True

	def unhook(self) ->bool:
		if self not in _ida().hooks:
			return False
		_ida().hooks.remove(self)
		return True

	def dbg_process_start(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size) ->None:
		pass

	def dbg_process_exit(self, pid, tid, ea, exit_code) ->None:
		pass

	def dbg_process_attach(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size) ->None:
		pass

	def dbg_process_detach(self, pid, tid, ea) ->None:
		pass

	def dbg_thread_start(self, pid, tid, ea) ->None:
		pass

	def dbg_thread_exit(self, pid, tid, ea, exit_code) ->None:
		pass

	def dbg_library_load(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size) ->None:
		pass

	def dbg_library_unload(self, pid, tid, ea, info) ->None:
		pass

	def dbg_information(self, pid, tid, ea, info) ->None:
		pass

	def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info) ->int:
		return 0

	def dbg_suspend_process(self) ->None:
		pass

	def dbg_bpt(self, tid, bptea) ->int:
		return 0

	def dbg_request_error(self, failed_command, failed_dbg_notification) ->None:
		pass

	def dbg_step_into(self) ->None:
		pass

	def dbg_step_over(self) ->None:
		pass

	def dbg_run_to(self, pid, tid, ea) ->None:
		pass

	def dbg_step_until_ret(self) ->None:
		pass

class bpt_location_t(object):
	''' Where a breakpoint is: an address (BPLT_ABS) or a module path and offset (BPLT_REL). '''

	def __init__(self):
		self._type = BPLT_ABS
		self._ea = 0xFFFFFFFFFFFFFFFF
		self._path = ''
		self._offset = 0

	def type(self):
		return self._type

	def path(self):
		return self._path

	def offset(self):
		return self._offset

	def ea(self):
		return self._ea

	def symbol(self):
		return ''

	def lineno(self):
		return 0

	def set_abs_bpt(self, a):
		self._type, self._ea = BPLT_ABS, a

	def set_rel_bpt(self, mod, _offset):
		self._type, self._path, self._offset = BPLT_REL, mod, _offset

class bpt_t(object):
	''' A breakpoint, as IDA describes it. Filled by `getn_bpt`, `get_bpt` and `find_bpt` with a copy. '''

	def __init__(self):
		self.loc = bpt_location_t()
		self.ea = 0xFFFFFFFFFFFFFFFF
		self.type = 4
		self.flags = BPT_BRK | BPT_ENABLED
		self.size = 0
		self.pass_count = 0

	def enabled(self):
		return bool(self.flags & BPT_ENABLED)

	def is_absbpt(self):
		return self.loc.type() == BPLT_ABS

	def is_relbpt(self):
		return self.loc.type() == BPLT_REL

	def set_abs_bpt(self, a):
		self.loc.set_abs_bpt(a)

	def set_rel_bpt(self, mod, o):
		self.loc.set_rel_bpt(mod, o)

# PROCESS

def get_process_state() ->int:
	return _ida().state

def start_process(path: str=None, args: str=None, sdir: str=None) ->int:
	return _ida().start_process(path, args, sdir)

def attach_process(*args) ->int:
	return _ida().attach_process(*args)

def exit_process() ->bool:
	return _ida().request('exit')

def detach_process() ->bool:
	return _ida().request('detach')

def suspend_process() ->bool:
	return _ida().request('suspend')

def continue_process() ->bool:
	return _ida().continue_process()

def request_continue_process() ->bool:
	_ida().ui_requests.append('continue')
	return True

def run_requests() ->bool:
	return _ida().run_requests()

def run_to(*args) ->bool:
	return _ida().run_to(args[0])

def wait_for_next_event(wfne: int, timeout: int) ->'dbg_event_code_t':
	return _ida().wait_for_next_event(wfne, timeout)

def get_debug_event() ->'debug_event_t const *':
	return _ida().event

def set_debugger_options(options: 'uint') ->'uint':
	old, _ida().options = _ida().options, options
	return old

def load_debugger(dbgname: str, use_remote: bool) ->bool:
	return _ida().load_debugger(dbgname, use_remote)

def dbg_is_loaded():
	return _ida().loaded is not None

# THREADS AND REGISTERS

def get_thread_qty() ->int:
	return len(_ida().threads)

def getn_thread(n: int) ->'thid_t':
	tids = sorted(_ida().threads)
	return tids[n] if 0 <= n < len(tids) else 0

def get_current_thread() ->'thid_t':
	return _ida().current_tid

def select_thread(tid: 'thid_t') ->bool:
	return _ida().select_thread(tid)

def get_reg_val(*args):
	return _ida().get_reg(args[0])

def set_reg_val(*args) ->bool:
	return _ida().set_reg(args[0], args[1])

def get_ip_val() ->'uint64 *':
	return _ida().get_reg('PC', None)

def get_sp_val() ->'uint64 *':
	return _ida().get_reg('SP', None)

def is_reg_integer(regname: str) ->bool:
	return regname in _ida().integer_registers

def collect_stack_trace(tid: 'thid_t', trace: 'call_stack_t') ->bool:
	return _ida().collect_stack_trace(tid, trace)

# MODULES

def get_first_module(modinfo: 'modinfo_t') ->bool:
	return _ida().module_after(None, modinfo)

def get_next_module(modinfo: 'modinfo_t') ->bool:
	return _ida().module_after(modinfo.base, modinfo)

# BREAKPOINTS

def get_bpt_qty() ->int:
	return len(_ida().bpts)

def getn_bpt(n: int, bpt: 'bpt_t') ->bool:
	bpts = _ida().bpts
	return 0 <= n < len(bpts) and _ida().fill_bpt(bpts[n], bpt)

def get_bpt(ea, bpt: 'bpt_t') ->bool:
	record = _ida().bpt_at(ea)
	return record is not None and _ida().fill_bpt(record, bpt)

def exist_bpt(ea) ->bool:
	return _ida().bpt_at(ea) is not None

def find_bpt(bptloc: 'bpt_location_t', bpt: 'bpt_t') ->bool:
	record = _ida().bpt_by_loc(bptloc)
	return record is not None and _ida().fill_bpt(record, bpt)

def add_bpt(*args) ->bool:
	return _ida().add_bpt(*args)

def del_bpt(*args) ->bool:
	return _ida().del_bpt(args[0])

def enable_bpt(*args) ->bool:
	return _ida().enable_bpt(args[0], args[1] if len(args) > 1 else True)

def disable_bpt(*args) ->bool:
	return _ida().enable_bpt(args[0], False)

def update_bpt(bpt: 'bpt_t') ->bool:
	record = _ida().bpt_by_loc(bpt.loc)
	if record is None:
		return False
	record['flags'] = bpt.flags
	return True
