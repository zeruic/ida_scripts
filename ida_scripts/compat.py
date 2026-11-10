''' Internal: everything that depends on the IDA version, or on how IDA is hosted, lives here. '''

import os
import sys
from typing import *

def _find_ida() -> bool:
	if os.environ.get('IDA_SCRIPTS_NO_IDA') == '1':
		return False
	try:
		import ida_idaapi
		return True
	except ImportError:
		pass
	path = list(sys.path)
	try:
		# A plain Python with idalib: idapro has to be imported before any ida_* module.
		import idapro
		import ida_idaapi
	except ImportError:
		return False
	# Starting idalib drops the entries the caller put at the front of sys.path, its own folder included.
	sys.path[:0] = [entry for entry in path if entry not in sys.path]
	return True

IN_IDA: bool = _find_ida()
''' Whether IDA's Python modules are available. False outside IDA (when generating the docs, for instance). '''

IDALIB: bool = IN_IDA and 'idapro' in sys.modules
''' Whether this process hosts IDA as a library (idalib) rather than running inside IDA. '''

BADADDR: int = 0xFFFFFFFFFFFFFFFF

if IN_IDA:
	import ida_idaapi
	import ida_pro
	import ida_ida
	import ida_nalt
	import ida_funcs
	import ida_range
	import ida_segment
	import ida_dbg
	import ida_idd

	if ida_pro.IDA_SDK_VERSION < 900:
		raise ImportError(f'ida_scripts needs IDA 9.0 or newer, this is SDK {ida_pro.IDA_SDK_VERSION}.')

	BADADDR = ida_idaapi.BADADDR
	# The address-based function and segment API arrived in 9.4. The fallbacks below are untested.
	_EA_API = hasattr(ida_funcs, 'get_func_entry_info')

IDA_VERSION: int = ida_pro.IDA_SDK_VERSION if IN_IDA else 0
''' The SDK version, 940 for IDA 9.4. 0 outside IDA. '''

_decompiler: Optional[bool] = None

# DATABASE

def is_64bit() -> bool:
	''' Whether the database is 64-bit. '''
	return ida_ida.inf_is_64bit()

def is_big_endian() -> bool:
	''' Whether the database is big-endian. '''
	return ida_ida.inf_is_be()

def image_base() -> int:
	''' The image base of the database. '''
	return ida_nalt.get_imagebase()

# FUNCTIONS

def func_start(ea: int) -> Optional[int]:
	''' Start of the function containing `ea`, `None` when it is in no function. '''
	if _EA_API:
		start = ida_funcs.get_func_start(ea)
		return None if start == BADADDR else start
	func = ida_funcs.get_func(ea)
	return func.start_ea if func else None

def _entry(start: int) -> 'ida_funcs.func_entry_info_t':
	info = ida_funcs.func_entry_info_t()
	if not ida_funcs.get_func_entry_info(info, start):
		raise LookupError(f'no function at {hex(start)}')
	return info

def func_end(start: int) -> int:
	''' End of the entry chunk of the function starting at `start`. '''
	if _EA_API:
		return _entry(start).end_ea
	return ida_funcs.get_func(start).end_ea

def func_chunks(start: int) -> List[Tuple[int, int]]:
	''' Every chunk of the function as `(start, end)`, in address order. '''
	if _EA_API:
		ranges = ida_range.rangeset_t()
		ida_funcs.get_func_ranges_ea(ranges, start)
		return sorted((r.start_ea, r.end_ea) for r in ranges)
	import idautils
	return sorted(idautils.Chunks(start))

def func_size(start: int) -> int:
	''' Size of the function in bytes, all chunks together. '''
	if _EA_API:
		return ida_funcs.calc_func_size_ea(start)
	return ida_funcs.calc_func_size(ida_funcs.get_func(start))

def func_flags(start: int) -> int:
	''' The `FUNC_*` flags of the function. '''
	if _EA_API:
		return ida_funcs.get_func_flags(start)
	return ida_funcs.get_func(start).flags

def func_comment(start: int, repeatable: bool = True) -> str:
	''' The function comment, `''` when there is none. '''
	if _EA_API:
		return ida_funcs.get_func_cmt_ea(start, repeatable) or ''
	return ida_funcs.get_func_cmt(ida_funcs.get_func(start), repeatable) or ''

def set_func_comment(start: int, text: str, repeatable: bool = True) -> bool:
	''' Set the function comment. '''
	if _EA_API:
		return ida_funcs.set_func_cmt_ea(start, text, repeatable)
	return ida_funcs.set_func_cmt(ida_funcs.get_func(start), text, repeatable)

def thunk_target(start: int) -> Optional[int]:
	''' Where a thunk function jumps to, `None` when the function is not a thunk. '''
	if not func_flags(start) & ida_funcs.FUNC_THUNK:
		return None
	if _EA_API:
		result = ida_funcs.calc_thunk_function_target(_entry(start))
	else:
		result = ida_funcs.calc_thunk_func_target(ida_funcs.get_func(start))
	target = result[0] if isinstance(result, tuple) else result
	return None if target == BADADDR else target

def func_count() -> int:
	''' Number of functions in the database. '''
	return ida_funcs.get_func_qty()

def func_starts() -> Iterator[int]:
	''' Start address of every function, in address order. '''
	if not _EA_API:
		import idautils
		yield from idautils.Functions()
		return
	if not ida_funcs.get_func_qty():
		return
	ea = ida_funcs.get_func_ea_by_num(0)
	while ea != BADADDR:
		yield ea
		ea = ida_funcs.get_next_func_ea(ea)

# SEGMENTS

def segment_name(ea: int) -> str:
	''' Name of the segment containing `ea`, `''` when it is in no segment. '''
	if _EA_API:
		return ida_segment.get_segment_name(ea) or ''
	seg = ida_segment.getseg(ea)
	return ida_segment.get_segm_name(seg) if seg else ''

def segment_bounds(ea: int) -> Optional[Tuple[int, int]]:
	''' `(start, end)` of the segment containing `ea`, `None` when it is in no segment. '''
	if _EA_API:
		info = ida_segment.segment_info_t()
		return (info.start_ea, info.end_ea) if ida_segment.get_segment_info(info, ea) else None
	seg = ida_segment.getseg(ea)
	return (seg.start_ea, seg.end_ea) if seg else None

# DECOMPILER

def has_decompiler() -> bool:
	''' Whether the Hex-Rays decompiler is available. Loads it on the first call. '''
	global _decompiler
	if _decompiler is None:
		import ida_hexrays
		_decompiler = bool(ida_hexrays.init_hexrays_plugin())
	return _decompiler

def decompile(start: int) -> Tuple[Optional['ida_hexrays.cfunc_t'], str]:
	''' Decompile the function starting at `start`. Returns `(cfunc, '')`, or `(None, reason)` on failure. '''
	import ida_hexrays
	if not has_decompiler():
		return None, 'the Hex-Rays decompiler is not available'
	failure = ida_hexrays.hexrays_failure_t()
	if hasattr(ida_hexrays, 'decompile_function'):
		cfunc = ida_hexrays.decompile_function(start, failure)
	else:
		cfunc = ida_hexrays.decompile_func(ida_funcs.get_func(start), failure)
	return (cfunc, '') if cfunc else (None, failure.desc())

def refresh_decompiler(ea: int = None):
	''' Drop cached pseudocode: of the function containing `ea`, or of every function when `ea` is `None`.

	Does nothing when there is no decompiler.
	'''
	if not has_decompiler():
		return
	import ida_hexrays
	if ea is None:
		ida_hexrays.clear_cached_cfuncs()
		return
	start = func_start(ea)
	if start is not None:
		ida_hexrays.mark_cfunc_dirty(start, False)

# DEBUGGER
# Tests replace `ida_dbg` and `ida_idd` in this module with a fake backend.

def debugger_active() -> bool:
	''' Whether a process is being debugged, running or suspended. '''
	return ida_dbg.get_process_state() != ida_dbg.DSTATE_NOTASK

def debugger_suspended() -> bool:
	''' Whether the debugged process is suspended. '''
	return ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP

def dbg_read(ea: int, size: int) -> Optional[bytes]:
	''' Read the debuggee's memory, `None` on failure. '''
	return ida_idd.dbg_read_memory(ea, size)

def dbg_write(ea: int, data: bytes) -> bool:
	''' Write the debuggee's memory. '''
	return bool(ida_idd.dbg_write_memory(ea, data))
