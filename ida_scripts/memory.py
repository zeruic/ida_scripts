'''
Provides class(es) for reading and writing memory, of the database or of the debugged process, and for looking at the code around an address.
'''

import struct
from typing import *

from . import compat
from .compat import IN_IDA
from .utils import *

if TYPE_CHECKING:
	from .func import Func
	from .module import Module

if IN_IDA:
	import ida_bytes
	import ida_name
	import ida_lines
	import ida_ua
	import ida_idp
	import ida_xref
	import idautils

__all__ = ['Pointer', 'ptr', 'Xref', 'Insn', 'disasm', 'STR_MAXLEN']

STR_MAXLEN = 10000

STR_CHUNK = 256

class Pointer:
	''' Represent an address.
	The `Pointer` class offers convenient access to read/write from a memory address.

	Init a `Pointer` object with `Pointer.__init__` or the shorthand `ptr`.

	A `Pointer` object provides convenient functions to read/write certain data types (integers, floats, string, pointer) to its address in memory.
	These methods take an optional `value` parameter. They read and return the value if `value` is `None`, write and return success/failure as a `bool` when `value` is not None.

	Reads come from the debugged process while one is being debugged, and from the database otherwise. Writes always go to the debugged process.

	`Pointer` can be added/subtracted from another `Pointer` or `int` to yield a new `Pointer`.
	'''

	default_string_encoding: str = 'utf-8'
	''' The default string encoding used by `Pointer.string`. Defaults to `'utf-8'`. '''

	# INIT
	def __init__(self, addr: Union[int, str, 'Pointer', 'Func']):
		''' Init with an address, a symbol name, or anything else that stands for an address. '''
		self.addr: int = to_ea(addr)

	# READ/WRITE
	def read(self, size: int, offset: int = 0) -> bytes:
		''' Read bytes from `self.addr + offset` of given size.

		Raises `IDAError` when the memory cannot be read.
		'''
		ea = self.addr + offset
		if size <= 0:
			return b''
		if compat.debugger_active():
			data = compat.dbg_read(ea, size)
			if data is None or len(data) != size:
				raise IDAError(f'cannot read {size} bytes at {hex(ea)} from the debugged process')
			return data
		result = ida_bytes.get_bytes_and_mask(ea, size)
		if not result or int.from_bytes(result[1], 'little') != (1 << size) - 1:
			raise IDAError(f'the database has no {size} bytes at {hex(ea)}')
		return result[0]

	def write(self, bytes: bytes, offset: int = 0, verify: bool = False) -> bool:
		''' Write bytes to `self.addr + offset` in the debugged process.

		Parameters
		----------
		bytes : bytes
			The data to write.
		offset : int, default = 0
		verify : bool, default = False
			Read the memory back and report whether it holds the data.

		Returns
		-------
		bool
			Whether the write succeeded.

		Raises
		------
		DebuggerError
			When no process is being debugged.
		'''
		if not compat.debugger_active():
			raise DebuggerError('writing memory needs a process that is being debugged')
		if not compat.dbg_write(self.addr + offset, bytes):
			return False
		return self.read(len(bytes), offset) == bytes if verify else True

	def swap(self, data: bytes, offset: int = 0) -> bytes:
		''' Write `data` to the debugged process and return the bytes it replaced. '''
		previous = self.read(len(data), offset)
		if not self.write(data, offset):
			raise DebuggerError(f'cannot write {len(data)} bytes at {hex(self.addr + offset)}')
		return previous

	# The following methods reads when `value` is None and writes otherwise.
	def read_write_with_struct(self, format: str, value: Union[int, float] = None) -> Union[int, float, bool]:
		''' Read/Write a value described by one `struct` format character. '''
		format = ('>' if compat.is_big_endian() else '<') + format
		if value is None:
			return struct.unpack(format, self.read(struct.calcsize(format)))[0]
		else:
			return self.write(struct.pack(format, value))

	def u8(self, value: int = None) -> Union[int, bool]:
		''' Read/Write uint8. '''
		return self.read_write_with_struct('B', value)

	def u16(self, value: int = None) -> Union[int, bool]:
		''' Read/Write uint16. '''
		return self.read_write_with_struct('H', value)

	def u32(self, value: int = None) -> Union[int, bool]:
		''' Read/Write uint32. '''
		return self.read_write_with_struct('I', value)

	def u64(self, value: int = None) -> Union[int, bool]:
		''' Read/Write uint64. '''
		return self.read_write_with_struct('Q', value)

	def s8(self, value: int = None) -> Union[int, bool]:
		''' Read/Write int8. '''
		return self.read_write_with_struct('b', value)

	def s16(self, value: int = None) -> Union[int, bool]:
		''' Read/Write int16. '''
		return self.read_write_with_struct('h', value)

	def s32(self, value: int = None) -> Union[int, bool]:
		''' Read/Write int32. '''
		return self.read_write_with_struct('i', value)

	def s64(self, value: int = None) -> Union[int, bool]:
		''' Read/Write int64. '''
		return self.read_write_with_struct('q', value)

	def f32(self, value: float = None) -> Union[float, bool]:
		''' Read/Write a 32-bit float. '''
		return self.read_write_with_struct('f', value)

	def f64(self, value: float = None) -> Union[float, bool]:
		''' Read/Write a 64-bit float. '''
		return self.read_write_with_struct('d', value)

	def array(self, format: str, count: int) -> List[Union[int, float]]:
		''' Read `count` consecutive values.

		Parameters
		----------
		format : str
			One `struct` format character, such as `'i'` for int32 or `'f'` for float.
		count : int
			How many values to read.

		Returns
		-------
		list
			The values, in the database's byte order.
		'''
		format = f'{">" if compat.is_big_endian() else "<"}{count}{format}'
		return list(struct.unpack(format, self.read(struct.calcsize(format))))

	def read_terminated(self, width: int = 1) -> bytes:
		''' Read up to a terminator of `width` zero bytes, the terminator not included. Stops after `STR_MAXLEN` bytes. '''
		data = b''
		while len(data) < STR_MAXLEN:
			size = STR_CHUNK
			while True:
				try:
					chunk = self.read(size, len(data))
					break
				except IDAError:
					# The chunk may run past the end of readable memory before the terminator does.
					if size == width:
						raise
					size = max(width, size // 4 // width * width)
			for i in range(0, len(chunk) - width + 1, width):
				if not any(chunk[i:i+width]):
					return data + chunk[:i]
			data += chunk
		return data[:STR_MAXLEN]

	def string(self, value: str = None, encoding: str = None, read_length: int = None) -> Union[str, bool]:
		''' Read/Write string, optionally specifying a custom encoding and length to read.

		Parameters
		----------
		value : str, default = None
			Value to be written, the function reads if it's `None`. No terminator is added.
		encoding : str, default = None
			Encoding to be used for reading/writing, specify `None` to use `Pointer.default_string_encoding`.
		read_length : int, defualt = None
			Length to read in bytes, leave None to read until `\\0`.

		Returns
		-------
		`str` or `bool`
			Either the read string, or a bool indicating whether write succeeded.
		'''
		if not encoding:
			encoding = Pointer.default_string_encoding
		if value is not None:
			return self.write(value.encode(encoding))
		data = self.read(read_length) if read_length is not None else self.read_terminated()
		return data.decode(encoding, 'backslashreplace')

	def wstring(self, value: str = None, read_length: int = None) -> Union[str, bool]:
		''' Read/Write a UTF-16 string.

		Parameters
		----------
		value : str, default = None
			Value to be written, the function reads if it's `None`. No terminator is added.
		read_length : int, default = None
			Length to read in 16-bit units, leave None to read until a zero unit.

		Returns
		-------
		`str` or `bool`
			Either the read string, or a bool indicating whether write succeeded.
		'''
		encoding = 'utf-16-be' if compat.is_big_endian() else 'utf-16-le'
		if value is not None:
			return self.write(value.encode(encoding))
		data = self.read(read_length * 2) if read_length is not None else self.read_terminated(2)
		return data.decode(encoding, 'backslashreplace')

	def ptr(self, value: Union['Pointer', int] = None) -> Union['Pointer', bool]:
		''' Read/Write pointer. '''
		method = self.u64 if compat.is_64bit() else self.u32
		if value is None:
			return Pointer(method())
		else:
			return method(to_ea(value))

	def hexdump_str(self, len: int = 100, offset: int = 0) -> str:
		''' Generate hexdump from `self.addr + offset` of specified length. '''
		return hexdump(self.read(len, offset), start_offset=self.addr + offset)

	def hexdump(self, len: int = 100, offset: int = 0):
		''' Print hexdump from `self.addr + offset` of specified length. '''
		print(self.hexdump_str(len, offset))

	# DATABASE
	@property
	def name(self) -> str:
		''' The name at this address, `''` when it has none. Assign to rename. '''
		return ida_name.get_name(self.addr) or ''

	@name.setter
	def name(self, name: str):
		if not self.rename(name):
			raise IDAError(f'cannot name {self} {name!r}')

	def rename(self, name: str, force: bool = False) -> bool:
		''' Name this address.

		Parameters
		----------
		name : str
			The new name. An empty string removes the name.
		force : bool, default = False
			When the name is taken, let IDA use a numbered variant such as `name_0`.

		Returns
		-------
		bool
			Whether the address was named.
		'''
		done = set_name(self.addr, name, force)
		if done:
			compat.refresh_decompiler()
		return done

	@property
	def comment(self) -> str:
		''' The comment at this address, the repeatable one when there is no regular one. Assign to set a regular comment. '''
		return ida_bytes.get_cmt(self.addr, False) or ida_bytes.get_cmt(self.addr, True) or ''

	@comment.setter
	def comment(self, text: str):
		if not self.set_comment(text):
			raise IDAError(f'cannot comment {self}')

	def set_comment(self, text: str, repeatable: bool = False) -> bool:
		''' Set the regular or the repeatable comment at this address. '''
		return bool(ida_bytes.set_cmt(self.addr, text, repeatable))

	@property
	def segment(self) -> str:
		''' Name of the segment containing this address, `''` when it is in none. '''
		return compat.segment_name(self.addr)

	@property
	def rva(self) -> int:
		''' Offset of this address from the database's image base. '''
		return self.addr - compat.image_base()

	@property
	def is_code(self) -> bool:
		''' Whether this address is the start of an instruction. '''
		return ida_bytes.is_code(ida_bytes.get_flags(self.addr))

	@property
	def func(self) -> Optional['Func']:
		''' The function containing this address, `None` when it is in no function. '''
		from .func import Func
		return Func.at(self.addr)

	@property
	def module(self) -> Optional['Module']:
		''' The module of the debugged process containing this address, `None` when there is none. '''
		from .module import Module
		return Module.containing(self.addr)

	def xrefs_to(self) -> List['Xref']:
		''' References to this address, ordinary flow from the previous instruction left out. '''
		return [Xref(x.frm, x.to, x.type) for x in idautils.XrefsTo(self.addr, 0) if x.type != ida_xref.fl_F]

	def xrefs_from(self) -> List['Xref']:
		''' References from this address, ordinary flow to the next instruction left out. '''
		return [Xref(x.frm, x.to, x.type) for x in idautils.XrefsFrom(self.addr, 0) if x.type != ida_xref.fl_F]

	def disasm(self, count: int = 1) -> List['Insn']:
		''' Decode `count` consecutive instructions starting here. Stops early at the first undecodable one. '''
		insns = []
		ea = self.addr
		for _ in range(count):
			try:
				insn = Insn(ea)
			except IDAError:
				break
			insns.append(insn)
			ea += insn.size
		return insns

	# OPERATORS
	def __add__(self, other: Union['Pointer', int]) -> 'Pointer':
		if type(other) is Pointer:
			other = other.addr
		return Pointer(self.addr + other)

	def __sub__(self, other: Union['Pointer', int]) -> 'Pointer':
		if type(other) is Pointer:
			other = other.addr
		return Pointer(self.addr - other)

	def __eq__(self, other: Union['Pointer', int]) -> bool:
		if type(other) is Pointer:
			other = other.addr
		return self.addr == other

	def __lt__(self, other: Union['Pointer', int]) -> bool:
		if type(other) is Pointer:
			other = other.addr
		return self.addr < other

	def __hash__(self) -> int:
		return hash(self.addr)

	def __int__(self) -> int:
		return self.addr

	def __index__(self) -> int:
		return self.addr

	# OPERATOR ALIASES
	# for chaining
	def add(self, other: Union['Pointer', int]) -> 'Pointer':
		''' `self + other`. '''
		return self + other

	def sub(self, other: Union['Pointer', int]) -> 'Pointer':
		''' `self - other`. '''
		return self - other

	def __repr__(self):
		return f'*{hex(self.addr)}'

def ptr(addr: Union[int, str, Pointer, 'Func']) -> Pointer:
	''' Initialise a `Pointer`. '''
	return Pointer(addr)

def set_name(ea: int, name: str, force: bool = False) -> bool:
	''' Name an address without refreshing the decompiler. Bulk renames call this, then refresh once. '''
	flags = ida_name.SN_CHECK | ida_name.SN_NOWARN
	if force:
		flags |= ida_name.SN_FORCE
	return bool(ida_name.set_name(ea, name, flags))

XREF_KINDS = {}
if IN_IDA:
	XREF_KINDS = {
		ida_xref.fl_CF : 'call',
		ida_xref.fl_CN : 'call',
		ida_xref.fl_JF : 'jump',
		ida_xref.fl_JN : 'jump',
		ida_xref.dr_R : 'read',
		ida_xref.dr_W : 'write',
		ida_xref.dr_O : 'offset',
	}

@auto_repr(['frm', 'to', 'kind', 'func'], { 'func' : lambda f: f.name })
class Xref:
	''' Represent one reference between two addresses. '''

	def __init__(self, frm: int, to: int, type: int):
		''' Init with both ends and IDA's reference type, one of the `fl_` and `dr_` constants of `ida_xref`. '''
		self.frm: Pointer = Pointer(frm)
		''' Where the reference comes from. '''
		self.to: Pointer = Pointer(to)
		''' Where it points. '''
		self.type: int = type
		''' IDA's reference type. '''

	@property
	def kind(self) -> str:
		''' What the reference does: `'call'`, `'jump'`, `'read'`, `'write'`, `'offset'` or `'other'`. '''
		return XREF_KINDS.get(self.type, 'other')

	@property
	def is_code(self) -> bool:
		''' Whether the reference comes from an instruction, as opposed to data such as a pointer table. '''
		return self.frm.is_code

	@property
	def func(self) -> Optional['Func']:
		''' The function containing the origin, `None` when it comes from outside any function. '''
		return self.frm.func

	def __hash__(self) -> int:
		return hash((self.frm.addr, self.to.addr, self.type))

	def __eq__(self, o: object) -> bool:
		return type(o) is Xref and hash(self) == hash(o)

@auto_repr(['address', 'text'], { 'address' : hex })
class Insn:
	''' Represent one instruction. '''

	def __init__(self, address: Union[int, str, Pointer]):
		''' Decode the instruction at an address. Raises `IDAError` when there is none. '''
		self.address: int = to_ea(address)
		''' Instruction address. '''
		insn = ida_ua.insn_t()
		flags = ida_bytes.get_flags(self.address)
		# Memory of a debugged process is often not defined as code yet, so undefined bytes decode while debugging.
		self.defined: bool = ida_bytes.is_code(flags)
		''' Whether the database defines this address as code. '''
		decodable = self.defined or (ida_bytes.is_unknown(flags) and compat.debugger_active())
		self.size: int = ida_ua.decode_insn(insn, self.address) if decodable else 0
		''' Instruction size in bytes. '''
		if self.size <= 0:
			raise IDAError(f'no instruction at {hex(self.address)}')
		self.is_call: bool = bool(ida_idp.is_call_insn(insn))
		''' Whether this is a call instruction. '''
		self.n_ops = 0
		for op in insn.ops:
			if op.type == ida_ua.o_void:
				break
			self.n_ops += 1

	@property
	def mnem(self) -> str:
		''' Mnemonic. '''
		if self.defined:
			return ida_ua.print_insn_mnem(self.address) or ''
		return self.text.split(None, 1)[0] if self.text else ''

	@property
	def ops(self) -> List[str]:
		''' Operands as text. '''
		if self.defined:
			return [ida_lines.tag_remove(ida_ua.print_operand(self.address, n) or '') for n in range(self.n_ops)]
		# IDA prints operands only for defined code, so take them from the line.
		rest = self.text.split(';')[0].split(None, 1)[1:]
		return split_operands(rest[0]) if rest else []

	@property
	def text(self) -> str:
		''' The disassembly line. '''
		return ida_lines.tag_remove(ida_lines.generate_disasm_line(self.address, ida_lines.GENDSM_FORCE_CODE) or '')

	@property
	def target(self) -> Optional[Pointer]:
		''' Where a direct call or jump goes, `None` for anything else. '''
		for x in idautils.XrefsFrom(self.address, 0):
			if XREF_KINDS.get(x.type) in ('call', 'jump'):
				return Pointer(x.to)
		return None

	@property
	def call_target(self) -> Optional['Func']:
		''' The function a direct call goes to, `None` for anything else. '''
		target = self.target if self.is_call else None
		return target.func if target else None

	def to_dict(self) -> Dict[str, Any]:
		''' The instruction as a JSON-friendly `dict`. '''
		return { 'address' : hex(self.address), 'mnem' : self.mnem, 'ops' : self.ops, 'text' : self.text }

	def __hash__(self) -> int:
		return self.address

	def __eq__(self, o: object) -> bool:
		return type(o) is Insn and self.address == o.address

def split_operands(text: str) -> List[str]:
	''' Split the operand part of a disassembly line at its top-level commas. '''
	operands, depth, current = [], 0, ''
	for char in text:
		if char in '[({':
			depth += 1
		elif char in '])}':
			depth -= 1
		if char == ',' and depth == 0:
			operands.append(current.strip())
			current = ''
		else:
			current += char
	if current.strip():
		operands.append(current.strip())
	return operands

def disasm(start: Union[int, str, Pointer], end: Union[int, str, Pointer]) -> List[Insn]:
	''' Every instruction in `[start, end)`, whether or not the range belongs to a function. '''
	start, end = to_ea(start), to_ea(end)
	insns = []
	ea = start
	while ea < end and ea != compat.BADADDR:
		if ida_bytes.is_code(ida_bytes.get_flags(ea)):
			insns.append(Insn(ea))
		ea = ida_bytes.next_head(ea, end)
	return insns
