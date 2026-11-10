''' Provides class(es) for the modules of the debugged process: where each one is loaded, and how its addresses map to the database. '''

from typing import *

from . import compat
from .compat import IN_IDA
from .utils import *
from .memory import Pointer

if IN_IDA:
	import ida_dbg
	import ida_idd
	import ida_nalt

__all__ = ['Module']

def file_name(path: str) -> str:
	''' The last part of a path, whether it uses `/` or `\\` as the separator. '''
	return path.replace('\\', '/').rsplit('/', 1)[-1]

def same_module(path: str, name: str) -> bool:
	''' Whether `name` (a full path or a file name) names the module at `path`. Ignores case. '''
	if not path or not name:
		return False
	path, name = path.replace('\\', '/').lower(), name.replace('\\', '/').lower()
	return path == name or file_name(path) == file_name(name)

@auto_repr(['name', 'addr', 'size'], { 'addr' : hex })
class Module:
	''' Represent a module (the executable or a library) loaded in the debugged process.

	Get one with `Module.find`, `Module.containing` or `Module.all_modules`, or from `Pointer.module`.

	`module + offset` is a `Pointer` into the module. `Module.to_static` and `Module.from_static` translate between the process and a database made from the module's file, which may be loaded at another base:

	```
	engine = Module.find('Engine.dll')
	engine.static_base = 0x10000000      # where the database has it
	ptr(engine.from_static(0x10004de0)).u32()
	```
	'''

	static_bases: Dict[str, int] = {}
	''' The `Module.static_base` given to each module, by lowercase file name. Kept across `Module` objects, so it is set once per module. '''

	def __init__(self, name: str, addr: int, size: int = 0):
		''' Init with the module's full path, its base address in the process and its size. '''
		self.name: str = name
		''' Full path of the module, as the debugger reports it. '''
		self.addr: int = addr
		''' Base address in the process. '''
		self.size: int = size
		''' Size in bytes, 0 when the debugger does not know it. '''

	@staticmethod
	def all_modules() -> List['Module']:
		''' Every module of the debugged process, by address. `[]` when no process is being debugged.

		The list comes from IDA. While IDA cannot list them (some debuggers cannot while the process runs), it is the list `dbg` keeps from the load and unload events.
		'''
		modules = Module._listed()
		if not modules:
			from .debugger import dbg
			modules = dbg.modules
		return modules

	@staticmethod
	def _listed() -> List['Module']:
		''' The modules IDA lists for the debugged process, by address. '''
		if not compat.debugger_active():
			return []
		info = ida_idd.modinfo_t()
		modules = []
		found = ida_dbg.get_first_module(info)
		while found:
			modules.append(Module(info.name, info.base, info.size))
			found = ida_dbg.get_next_module(info)
		return sorted(modules, key=lambda m: m.addr)

	@staticmethod
	def find(name: str) -> Optional['Module']:
		''' The module with this full path or file name, ignoring case. `None` when it is not loaded. '''
		return next((m for m in Module.all_modules() if same_module(m.name, name)), None)

	@staticmethod
	def containing(addr: Union[int, str, Pointer]) -> Optional['Module']:
		''' The module whose memory holds `addr`, `None` when there is none. '''
		ea = to_ea(addr)
		return next((m for m in Module.all_modules() if m.contains(ea)), None)

	def contains(self, addr: Union[int, str, Pointer]) -> bool:
		''' Whether `addr` is inside this module. Always false when the size is unknown. '''
		return self.addr <= to_ea(addr) < self.addr + self.size

	@property
	def is_input_file(self) -> bool:
		''' Whether this module is the file the database was made from. '''
		path = ida_nalt.get_input_file_path() or ''
		root = ida_nalt.get_root_filename() or ''
		return same_module(self.name, path) or (bool(root) and file_name(self.name).lower() == root.lower())

	@property
	def static_base(self) -> Optional[int]:
		''' Where the database has this module's base. Assign to set it, `None` to forget it.

		Defaults to the database's image base when this module is the database's input file, `None` (unknown) for any other module.
		'''
		key = file_name(self.name).lower()
		if key in Module.static_bases:
			return Module.static_bases[key]
		return compat.image_base() if self.is_input_file else None

	@static_base.setter
	def static_base(self, value: Optional[int]):
		key = file_name(self.name).lower()
		if value is None:
			Module.static_bases.pop(key, None)
		else:
			Module.static_bases[key] = to_ea(value)

	def _known_static_base(self) -> int:
		base = self.static_base
		if base is None:
			raise IDAError(f'the database address of {file_name(self.name)} is unknown, set its static_base first')
		return base

	def to_static(self, addr: Union[int, str, Pointer]) -> int:
		''' Translate an address in the process to the matching address in the database.

		Raises `IDAError` when `Module.static_base` is unknown or the address is outside the module.
		'''
		ea = to_ea(addr)
		if self.size and not self.contains(ea):
			raise IDAError(f'{hex(ea)} is not inside {file_name(self.name)} ({hex(self.addr)}-{hex(self.addr + self.size)})')
		return ea - self.addr + self._known_static_base()

	def from_static(self, ea: Union[int, str, Pointer]) -> Pointer:
		''' Translate an address in the database to the matching address in the process.

		Raises `IDAError` when `Module.static_base` is unknown or the address is outside the module.
		'''
		ea = to_ea(ea)
		base = self._known_static_base()
		if self.size and not base <= ea < base + self.size:
			raise IDAError(f'{hex(ea)} is not inside {file_name(self.name)} in the database ({hex(base)}-{hex(base + self.size)})')
		return Pointer(ea - base + self.addr)

	# OPERATORS
	def __add__(self, offset: int) -> Pointer:
		return Pointer(self.addr + offset)

	def __eq__(self, other: object) -> bool:
		return type(other) is Module and (self.name, self.addr) == (other.name, other.addr)

	def __hash__(self) -> int:
		return hash((self.name, self.addr))
