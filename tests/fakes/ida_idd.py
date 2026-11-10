''' Fake `ida_idd`: the subset of IDA 9.4's names that ida_scripts uses, with the same parameters, run against `process.current`. '''

import ida_idaapi as _idaapi
import ida_typeinf as _typeinf
import ida_bytes as _bytes
import ida_name as _name

from . import process as _process

# Values as in IDA 9.4, checked against the real module by tests/test_debugger.py.
NO_EVENT = 0
PROCESS_STARTED = 1
PROCESS_EXITED = 2
THREAD_STARTED = 3
THREAD_EXITED = 4
BREAKPOINT = 5
STEP = 6
EXCEPTION = 7
LIB_LOADED = 8
LIB_UNLOADED = 9
INFORMATION = 10
PROCESS_ATTACHED = 11
PROCESS_DETACHED = 12
PROCESS_SUSPENDED = 13
BPT_SOFT = 4
BPT_DEFAULT = 12
NO_THREAD = 0
NO_PROCESS = 4294967295

def _ida():
	return _process.current

class modinfo_t(object):
	''' A module of the process. '''

	def __init__(self):
		self.name = ''
		self.base = 0
		self.size = 0
		self.rebase_to = 0xFFFFFFFFFFFFFFFF

class excinfo_t(object):
	''' What an EXCEPTION event carries. '''

	def __init__(self):
		self.code = 0
		self.can_cont = True
		self.ea = 0xFFFFFFFFFFFFFFFF
		self.info = ''

class debug_event_t(object):
	''' One debugger event. '''

	def __init__(self, *args):
		self.pid = 0
		self.tid = 0
		self.ea = 0xFFFFFFFFFFFFFFFF
		self.handled = False
		self._eid = NO_EVENT
		self._modinfo = modinfo_t()
		self._info = ''
		self._exc = excinfo_t()
		self._exit_code = 0
		self._run_to = False

	def eid(self):
		return self._eid

	def modinfo(self):
		return self._modinfo

	def info(self):
		return self._info

	def exc(self):
		return self._exc

	def exit_code(self):
		return self._exit_code

class call_stack_info_t(object):
	''' One frame of a call stack. '''

	def __init__(self):
		self.callea = 0xFFFFFFFFFFFFFFFF
		self.funcea = 0xFFFFFFFFFFFFFFFF
		self.fp = 0xFFFFFFFFFFFFFFFF
		self.funcok = False

class call_stack_t(object):
	''' A call stack, filled by `ida_dbg.collect_stack_trace`. '''

	def __init__(self):
		self._frames = []

	def append(self, x):
		self._frames.append(x)

	def __len__(self):
		return len(self._frames)

	def __getitem__(self, i):
		return self._frames[i]

	def __iter__(self):
		return iter(list(self._frames))

def dbg_read_memory(ea, sz):
	return _ida().read(ea, sz)

def dbg_write_memory(ea, buffer):
	return _ida().write(ea, buffer)

def dbg_get_registers():
	if _ida().loaded is None:
		return None
	return [(name, 0, 1, 0, None, 0) for name in _ida().registers]

def dbg_get_name():
	return _ida().loaded

class Appcall_callable__(object):
	''' A function of the process, callable with Python values. '''

	def __init__(self, ea, tinfo_or_typestr=None, fields=None):
		self.__ea = ea
		self.__tif = tinfo_or_typestr

	@property
	def ea(self):
		return self.__ea

	def __call__(self, *args):
		return _ida().appcall(self.__ea, self.__tif, args)

class Appcall__(object):
	''' Calls into the process. '''

	def __init__(self):
		pass

	@staticmethod
	def proto(name_or_ea, proto_or_tinfo, flags=None):
		ea = _name.get_name_ea(_idaapi.BADADDR, name_or_ea) if isinstance(name_or_ea, str) else name_or_ea
		if ea == _idaapi.BADADDR or not _bytes.is_mapped(ea):
			raise AttributeError(f'Undefined function {name_or_ea}')
		tif = _typeinf.tinfo_t()
		if _typeinf.parse_decl(tif, None, proto_or_tinfo, flags or (_typeinf.PT_SIL | _typeinf.PT_NDC | _typeinf.PT_TYP)) is None:
			raise ValueError('Could not parse type: ' + proto_or_tinfo)
		return Appcall_callable__(ea, tif)

	@staticmethod
	def int64(v):
		return _idaapi.PyIdc_cvt_int64__(v)

	@staticmethod
	def byref(val):
		return _idaapi.PyIdc_cvt_refclass__(val)

	@staticmethod
	def UTF16(s):
		return _idaapi.as_UTF16(s)
	unicode = UTF16

Appcall = Appcall__()
