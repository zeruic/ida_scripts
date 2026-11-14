''' Provides class(es) for interacting with structures (definition and instances in memory). '''

import os
import re
import struct
from typing import *

from . import compat
from .compat import IN_IDA
from .memory import Pointer
from .utils import *

if IN_IDA:
	import ida_typeinf
	import ida_kernwin

__all__ = ['MemberT', 'StrucT', 'StrucI', 'parse_declaration', 'apply_prototypes']

@auto_repr(['id', 'name', 'dtype', 'offset', 'size'], { 'offset' : hex, 'id' : hex })
class MemberT:
	''' Represent a member of a struct type.

	A `MemberT` holds the member's id, so it follows the member through later changes to the struct. IDA gives the id of a deleted member to a member it creates later (the gap left in its place, for instance), so do not keep using the `MemberT` of a deleted member.
	'''

	def __init__(self, id: int, struct: 'StrucT'):
		''' Init with the member id (its tid) and the struct type containing it. '''
		self.id: int = id
		''' Member id (its tid). '''
		self.struct: 'StrucT' = struct
		''' The struct type containing this member. '''

	@property
	def udm(self) -> 'ida_typeinf.udm_t':
		''' The member as IDA describes it now, a fresh `ida_typeinf.udm_t` (offset and size in bits). Raises `IDAError` when the member is gone. '''
		udm = ida_typeinf.udm_t()
		if ida_typeinf.tinfo_t().get_udm_by_tid(udm, self.id) < 0:
			raise IDAError(f'the member {hex(self.id)} of {self.struct.name} no longer exists')
		return udm

	@property
	def name(self) -> str:
		''' Member name. '''
		return self.udm.name

	@property
	def dtype(self) -> 'ida_typeinf.tinfo_t':
		''' Member type, represented with `ida_typeinf.tinfo_t`. '''
		return self.udm.type

	@property
	def offset(self) -> int:
		''' Member offset in struct, in bytes. '''
		return self.udm.offset // 8

	@property
	def size(self) -> int:
		''' Member size in bytes. A bitfield counts the bytes its bits touch. '''
		return span(self.udm)[1]

	@property
	def is_gap(self) -> bool:
		''' Whether the member is a gap: a single or array of `char` or `_BYTE`, with a name starting with `gap`. '''
		return is_gap(self.udm)

	def instance_at(self, addr: Union[int, str, Pointer]) -> Any:
		''' Get the value from the given address.

		This method reads and parses the value at the given address using the appropriate type.

		Parameters
		----------
		addr : `Pointer`
			Where the member is (not the struct containing it).

		Returns
		-------
		int, float, bytes, list, `Pointer` or `StrucI`
			The parsed value, see `StrucI.__getitem__`.
		'''
		udm = self.udm
		addr = Pointer(addr)
		return member_value(udm, addr.read(span(udm)[1]), addr.addr)

	def instance_at_struct(self, struct_addr: Union[int, str, Pointer]) -> Any:
		''' Get the value from a struct at the given address.

		Identical to `instance_at` but applies the offset of this member.

		Parameters
		----------
		struct_addr : `Pointer`
			A pointer to an instance of the struct.

		Returns
		-------
		int, float, bytes, list, `Pointer` or `StrucI`
			The parsed value.
		'''
		return self.instance_at(Pointer(struct_addr) + self.offset)

	def __hash__(self) -> int:
		return self.id

	def __eq__(self, o: object) -> bool:
		return type(o) is MemberT and self.id == o.id

@auto_repr(['id', 'name', 'size'], { 'id' : hex })
class StrucT:
	''' Represent a struct type, a struct or union of the database's local types.

	A `StrucT` holds the type's id and asks IDA each time, so it reflects every change made to the type, through it or not.
	'''

	@staticmethod
	def find(name: str) -> Optional['StrucT']:
		''' Find struct type by name, `None` when there is none. `'struct Player'` works too, and a typedef name finds the struct it stands for. '''
		try:
			return StrucT(name)
		except LookupError:
			return None

	@staticmethod
	def create(name: str) -> 'StrucT':
		''' Create and return an empty struct. Raises `IDAError` when the name is taken or not acceptable. '''
		if ida_typeinf.get_type_ordinal(None, name):
			raise IDAError(f'cannot create the struct {name!r}: a local type of that name exists')
		tif = ida_typeinf.tinfo_t()
		code = tif.set_named_type(None, name) if tif.create_udt(ida_typeinf.udt_type_data_t()) else None
		if code != ida_typeinf.TERR_OK:
			raise IDAError(f'cannot create the struct {name!r}: {ida_typeinf.tinfo_errstr(code) if code is not None else "no empty struct"}')
		return StrucT(tif.get_tid())

	@staticmethod
	def parse(declaration: str) -> List['StrucT']:
		''' Declare types from C text, which may hold several declarations.

		A struct the database already has is replaced by the new definition. When the text has an error, IDA keeps the declarations it could parse.

		Parameters
		----------
		declaration : str
			C declarations, such as `'struct Vec2 { float x; float y; };'`.

		Returns
		-------
		List[`StrucT`]
			The structs and unions the text defines, in order, also those it redefines.

		Raises
		------
		IDAError
			When the text does not parse, with IDA's messages when it gives any.
		'''
		parse_c(declaration, 0, 'the declaration')
		structs = [StrucT.find(name) for name in defined_names(declaration)]
		return [s for s in structs if s]

	@staticmethod
	def import_header(path: str) -> int:
		''' Declare the types of a C header file, as File > Load file > Parse C header file does.

		When the header has an error, IDA keeps the declarations it could parse.

		Returns
		-------
		int
			How many named types the database did not have before.

		Raises
		------
		IDAError
			When the file does not exist or does not parse, with IDA's messages when it gives any.
		'''
		if not os.path.isfile(path):
			raise IDAError(f'cannot import {path}: no such file')
		before = set(ida_typeinf.get_idati().type_names)
		parse_c(path, ida_typeinf.HTI_FIL, path)
		return len(set(ida_typeinf.get_idati().type_names) - before)

	def __init__(self, target: Union[int, str, 'ida_typeinf.tinfo_t']):
		''' Init with the type id (tid), the name, or an `ida_typeinf.tinfo_t` of a struct or union. Raises `LookupError` when it is none. '''
		tif = ida_typeinf.tinfo_t()
		if isinstance(target, str):
			name = re.sub(r'^(?:(?:const|volatile|struct|union)\s+)+', '', target.strip())
			found = bool(name) and tif.get_named_type(None, name)
		elif isinstance(target, int):
			found = tif.get_type_by_tid(target)
		else:
			tif, found = target, True
		tid = udt_id(tif) if found else None
		if tid is None:
			raise LookupError(f'no struct {hex(target) if isinstance(target, int) else repr(str(target))} in the local types')
		self.id: int = tid
		''' Struct id (its tid). '''

	@property
	def tif(self) -> 'ida_typeinf.tinfo_t':
		''' The type as IDA has it now. Editing this `ida_typeinf.tinfo_t` edits the type in the database. Raises `IDAError` when the type is gone. '''
		tif = ida_typeinf.tinfo_t()
		if not tif.get_type_by_tid(self.id):
			raise IDAError(f'the struct {hex(self.id)} no longer exists')
		return tif

	@property
	def name(self) -> str:
		''' Struct name. '''
		return ida_typeinf.get_tid_name(self.id) or ''

	@property
	def declaration(self) -> str:
		''' The struct as C text, ready for `StrucT.parse`. '''
		flags = ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_SEMI
		return (self.tif._print(self.name, flags, 2) or '').strip()

	@property
	def members(self) -> List[MemberT]:
		''' All member types of struct, in order. Gaps IDA keeps between members are members too. '''
		tif = self.tif
		return [MemberT(tif.get_udm_tid(i), self) for i in range(tif.get_udt_nmembers())]

	@property
	def size(self) -> int:
		''' Struct size in bytes. '''
		return self.tif.get_size()

	def instance_at(self, addr: Union[int, str, Pointer]) -> 'StrucI':
		''' Get an instance of this struct at the given address. '''
		return StrucI(addr, self)

	def __getitem__(self, name: str) -> Optional[MemberT]:
		''' Get a member type by name, `None` when there is none. '''
		tif = self.tif
		index = tif.find_udm(name)
		return MemberT(tif.get_udm_tid(index), self) if index >= 0 else None

	def member_at_offset(self, offset: int) -> Optional[MemberT]:
		''' Get the member type containing a byte offset, `None` when no member covers it. '''
		tif = self.tif
		index = tif.get_udm_by_offset(offset * 8)[0] if offset >= 0 else -1
		return MemberT(tif.get_udm_tid(index), self) if index is not None and index >= 0 else None

	def member_starting_at_offset(self, offset: int) -> Optional[MemberT]:
		''' Get a member type by offset, member must start at offset. '''
		member = self.member_at_offset(offset)
		return member if member and member.offset == offset else None

	# MUTATING METHODS
	# Each of them refreshes the decompiler, so pseudocode shows the change.

	def add_member(self, declaration: str, offset: int) -> MemberT:
		''' Create and return a new member in this struct type.

		Parameters
		----------
		declaration : str
			A C declaration of one member, such as `'int count'`, `'char name[16]'` or `'struct Vec2 *where'`.
		offset : int
			Where the member starts, in bytes. It may lie in a gap IDA keeps, or past the end.

		Raises
		------
		IDAError
			When the declaration does not parse, or IDA refuses the member (it overlaps another one, for instance), with IDA's reason.
		'''
		return self._insert(declaration, offset, 0)

	def add_gap(self, offset: int, size: int) -> MemberT:
		''' Create and return a new member representing a bytes gap, `_BYTE gapXX[size]`.

		IDA keeps the holes inside a struct as gap members of that form itself, so when exactly that gap is already there, it is returned. Raises `IDAError` when a member that is not a gap is in the way.
		'''
		existing = self.member_starting_at_offset(offset)
		if existing and existing.is_gap and existing.size == size:
			return existing
		self._gaps_in(offset, offset + size, f'a gap of {size} bytes')
		return self._insert(f'_BYTE gap{to_hex(offset)}[{size}]', offset, ida_typeinf.ETF_MAY_DESTROY)

	def delete_member(self, member: Union[MemberT, str]) -> bool:
		''' Delete a given member, or the member of that name. A member in the middle leaves a gap, the last one shrinks the struct. '''
		member = self[member] if isinstance(member, str) else member
		owner = ida_typeinf.tinfo_t()
		index = owner.get_udm_by_tid(ida_typeinf.udm_t(), member.id) if member else -1
		if index < 0 or owner.get_tid() != self.id:
			return False
		done = owner.del_udm(index) == ida_typeinf.TERR_OK
		compat.refresh_decompiler()
		return done

	def add_member_auto(self, declaration: str, offset: int) -> MemberT:
		''' Create and return a new member in this struct type, automatically reworking gaps.

		`declaration` is as for `add_member`, such as `'int count'` or `'char name[16]'`.

		A gap is recognised by:
		1. Is a single or array of 'char' or '_BYTE'.
		2. Name starting with 'gap' (all lowercase).

		If the new member falls within gaps of the above definition, they are split around it: what is left before and after it stays a gap, named after its offset.

		Raises
		------
		IDAError
			When a member that is not a gap is in the way (nothing changes then), or IDA refuses the member.
		'''
		dtype, _ = parse_declaration(declaration)
		end = offset + dtype.get_size()
		gaps = self._gaps_in(offset, end, repr(declaration))
		if not gaps:
			return self.add_member(declaration, offset)
		gap_start = min(gap.offset for gap in gaps)
		gap_end = max(gap.offset + gap.size for gap in gaps)
		member = self._insert(declaration, offset, ida_typeinf.ETF_MAY_DESTROY)
		# IDA keeps the part before the member as a gap itself, the part past a new end of the struct is gone.
		if offset > gap_start:
			self.add_gap(gap_start, offset - gap_start)
		if end < gap_end:
			self.add_gap(end, gap_end - end)
		return member

	def _insert(self, declaration: str, offset: int, flags: int) -> MemberT:
		''' Add a member with `ida_typeinf.tinfo_t.add_udm` flags (`ETF_*`). `ETF_MAY_DESTROY` replaces whatever it overlaps. '''
		dtype, name = parse_declaration(declaration)
		try:
			self.tif.add_udm(ida_typeinf.udm_t(name, dtype, offset * 8), flags)
		except ValueError as error:
			raise IDAError(f'cannot add {declaration!r} at {hex(offset)} to {self.name}: {error}') from None
		finally:
			compat.refresh_decompiler()
		return self[name]

	def _gaps_in(self, start: int, end: int, what: str) -> List[MemberT]:
		''' The gap members in `[start, end)`. Raises `IDAError` when a member that is not a gap is there. '''
		tif = self.tif
		overlapping = []
		for index, udm in enumerate(udms(tif)):
			first, size = span(udm)
			if first < end and start < first + size:
				if not is_gap(udm):
					raise IDAError(f'cannot add {what} at {hex(start)} to {self.name}: {udm.name} is in the way')
				overlapping.append(MemberT(tif.get_udm_tid(index), self))
		return overlapping

	def __hash__(self) -> int:
		return self.id

	def __eq__(self, o: object) -> bool:
		return type(o) is StrucT and self.id == o.id

@auto_repr(['addr', 'struc_t'])
class StrucI:
	''' Represent a struct instance.

	Reads come from the debugged process while one is being debugged, and from the database otherwise. Writes go to the debugged process (see `Pointer`).
	'''

	def __init__(self, addr: Union[int, str, Pointer], struc_t: Union[StrucT, str]):
		''' Init with a base address and a struct type (or its name). '''
		self.addr: Pointer = Pointer(addr)
		''' The address of this struct. '''
		self.struc_t: StrucT = struc_t if isinstance(struc_t, StrucT) else StrucT(struc_t)
		''' The type definition of this struct. '''

	@property
	def members(self) -> Dict[str, Any]:
		''' Collect all members of this struct as a dict of their values, reading the struct once. '''
		data = self.addr.read(self.struc_t.size)
		values = {}
		for udm in udms(self.struc_t.tif):
			start, size = span(udm)
			values[udm.name] = member_value(udm, data[start:start + size], self.addr.addr + start)
		return values

	def to_dict(self) -> Dict[str, Any]:
		''' The members' values as a JSON-friendly `dict`: pointers as hex strings, a `char` array as its text up to the first zero, other bytes in hex, nested structs as dicts. '''
		values = self.members
		for udm in udms(self.struc_t.tif):
			if udm.type.is_array() and udm.type.get_array_element().is_char():
				values[udm.name] = values[udm.name].split(b'\0', 1)[0].decode(Pointer.default_string_encoding, 'backslashreplace')
		return { name : jsonable(value) for name, value in values.items() }

	def member(self, name: str, return_pointer: bool = True) -> Any:
		''' Get a member's `Pointer`, or its value with `return_pointer=False`. `None` when there is no such member. '''
		member = self.struc_t[name]
		if not member:
			return None
		return self.addr + member.offset if return_pointer else member.instance_at_struct(self.addr)

	def ptr(self, name: str) -> Pointer:
		''' The address of a member. Raises `KeyError` when there is no such member. '''
		return self.addr + self._member(name).offset

	def __getitem__(self, name: str) -> Any:
		''' Get a member's value by its name.

		Integers by size and sign (`bool` as `bool`), `float` and `double` as `float`, a pointer as a `Pointer` to what it points at, a `char` (or `_BYTE`) array as `bytes`, any other array as a list, a nested struct as a `StrucI`, a bitfield as an `int`.

		Raises `KeyError` when there is no such member.
		'''
		return self._member(name).instance_at_struct(self.addr)

	def __setitem__(self, name: str, value: Any) -> bool:
		''' Set a member's value by its name, in the debugged process.

		Takes what reading gives: an `int` (a pointer also takes a `Pointer` or a symbol name), a `float`, `bytes` or `str` for a `char` array (zero-padded to its size), a list for another array (it may be shorter than the array), a `dict` of member values or a `StrucI` for a nested struct, and `bytes` of the member's exact size for anything.

		Returns
		-------
		bool
			Whether the write succeeded.

		Raises
		------
		KeyError
			When there is no such member.
		TypeError, ValueError
			When the value does not suit the member.
		DebuggerError
			When no process is being debugged.
		'''
		udm = self._member(name).udm
		start, size = span(udm)
		where = self.addr + start
		if udm.type.is_udt() and isinstance(value, dict):
			nested = StrucI(where, StrucT(udm.type))
			return all([nested.__setitem__(key, item) for key, item in value.items()])
		if udm.is_bitfield():
			return where.write(bitfield_bytes(udm, where.read(size), value))
		return where.write(encode(udm.type, value, size))

	def _member(self, name: str) -> MemberT:
		''' The member of that name. Raises `KeyError` when there is none. '''
		member = self.struc_t[name]
		if not member:
			raise KeyError(f'{self.struc_t.name} has no member {name!r}')
		return member

	def __hash__(self) -> int:
		return hash((self.struc_t.id, self.addr.addr))

	def __eq__(self, o: object) -> bool:
		return type(o) is StrucI and self.struc_t == o.struc_t and self.addr == o.addr

def parse_declaration(declaration: str) -> Tuple['ida_typeinf.tinfo_t', str]:
	''' Parse the C declaration of one member, such as `'unsigned int count'` or `'char name[16]'`.

	Returns
	-------
	(`ida_typeinf.tinfo_t`, str)
		The type and the name.

	Raises
	------
	IDAError
		When it is not a declaration of one named member.
	'''
	text = declaration.strip()
	tif = ida_typeinf.tinfo_t()
	name = ida_typeinf.parse_decl(tif, None, text if text.endswith(';') else text + ';', ida_typeinf.PT_SIL | ida_typeinf.PT_VAR | ida_typeinf.PT_NDC)
	if not name or tif.empty() or tif.is_func():
		raise IDAError(f'cannot parse {declaration!r}: a member declaration is like `TYPE NAME` or `TYPE NAME[SIZE]`')
	return tif, name

def apply_prototypes(prototypes: Dict[Union[int, str, Pointer], str]) -> int:
	''' Apply C prototypes to functions, refreshing the decompiler once at the end.

	Parameters
	----------
	prototypes : dict
		Function address (or anything else that stands for one) to its C prototype, such as `'int __fastcall add(int a, int b)'`.

	Returns
	-------
	int
		How many prototypes were applied. An address in no function, or a prototype IDA refuses, is skipped.
	'''
	from .func import set_prototype
	applied = 0
	try:
		for target, prototype in prototypes.items():
			try:
				start = compat.func_start(to_ea(target))
			except LookupError:
				continue
			if start is not None and set_prototype(start, prototype):
				applied += 1
	finally:
		compat.refresh_decompiler()
	return applied

# TYPES

def udt_id(tif: 'ida_typeinf.tinfo_t') -> Optional[int]:
	''' The tid of the struct or union a type is, or names through a typedef, `None` when it is none. '''
	if not tif.is_udt():
		return None
	if tif.is_typedef():
		final = ida_typeinf.tinfo_t()
		if not final.get_named_type(None, tif.get_final_type_name() or ''):
			return None
		tif = final
	tid = tif.get_tid()
	return None if tid == compat.BADADDR else tid

def udms(tif: 'ida_typeinf.tinfo_t') -> List['ida_typeinf.udm_t']:
	''' Copies of every member of a struct or union. '''
	details = ida_typeinf.udt_type_data_t()
	return [ida_typeinf.udm_t(udm) for udm in details] if tif.get_udt_details(details) else []

def is_gap(udm: 'ida_typeinf.udm_t') -> bool:
	''' See `MemberT.is_gap`. '''
	return str(udm.type)[:4] in ['char', '_BYT'] and udm.name.startswith('gap')

def span(udm: 'ida_typeinf.udm_t') -> Tuple[int, int]:
	''' `(offset, size)` in bytes of the bytes a member touches. '''
	start = udm.offset // 8
	return start, (udm.offset + udm.size + 7) // 8 - start

def is_byte(tif: 'ida_typeinf.tinfo_t') -> bool:
	''' Whether a type is a `char`, an `unsigned char` or a `_BYTE`, so an array of it reads as `bytes`. '''
	return tif.get_size() == 1 and (tif.is_char() or tif.is_uchar() or tif.get_realtype() == ida_typeinf.BTF_BYTE)

def byte_order() -> str:
	''' The database's byte order, for `int.from_bytes`. '''
	return 'big' if compat.is_big_endian() else 'little'

def float_format(size: int) -> str:
	''' The `struct` format of a float of that size. '''
	return ('>' if compat.is_big_endian() else '<') + { 4 : 'f', 8 : 'd' }[size]

# VALUES

def decode(dtype: 'ida_typeinf.tinfo_t', data: bytes, addr: int) -> Any:
	''' The value of type `dtype` that `data` holds, `data` being read at `addr`. A type with no better form gives the bytes. '''
	if dtype.is_udt():
		tid = udt_id(dtype)
		return StrucI(addr, StrucT(tid)) if tid is not None else data
	if dtype.is_array():
		element = dtype.get_array_element()
		size = element.get_size()
		if is_byte(element) or not 0 < size < compat.BADADDR:
			return data
		return [decode(element, data[i * size:(i + 1) * size], addr + i * size) for i in range(len(data) // size)]
	if dtype.is_ptr():
		return Pointer(int.from_bytes(data, byte_order()))
	if dtype.is_floating() and len(data) in (4, 8):
		return struct.unpack(float_format(len(data)), data)[0]
	if dtype.is_bool():
		return any(data)
	if dtype.is_integral() or dtype.is_enum():
		return int.from_bytes(data, byte_order(), signed=dtype.is_signed())
	return data

def member_value(udm: 'ida_typeinf.udm_t', data: bytes, addr: int) -> Any:
	''' The value of a member, `data` being the bytes it touches, read at `addr`. '''
	if not udm.is_bitfield():
		return decode(udm.type, data, addr)
	value = int.from_bytes(data, byte_order()) >> (udm.offset % 8) & ((1 << udm.size) - 1)
	if udm.type.is_signed() and value >> (udm.size - 1):
		value -= 1 << udm.size
	return value

def encode(dtype: 'ida_typeinf.tinfo_t', value: Any, size: int) -> bytes:
	''' The bytes that hold `value` as a `size` bytes long `dtype`. Shorter for a list that fills only the start of an array. '''
	element = dtype.get_array_element() if dtype.is_array() else None
	if element is not None and is_byte(element) and isinstance(value, (str, bytes, bytearray)):
		data = value.encode(Pointer.default_string_encoding) if isinstance(value, str) else bytes(value)
		if len(data) > size:
			raise ValueError(f'{len(data)} bytes do not fit in {dtype}')
		return data.ljust(size, b'\0')
	if isinstance(value, (bytes, bytearray)):
		if len(value) != size:
			raise ValueError(f'{dtype} takes {size} bytes, not {len(value)}')
		return bytes(value)
	if element is not None and isinstance(value, (list, tuple)):
		width = element.get_size()
		if len(value) * width > size:
			raise ValueError(f'{len(value)} values do not fit in {dtype}')
		return b''.join(encode(element, item, width) for item in value)
	if dtype.is_udt() and isinstance(value, StrucI):
		return value.addr.read(size)
	if dtype.is_ptr():
		return integer_bytes(to_ea(value), size * 8)
	if dtype.is_floating() and size in (4, 8) and isinstance(value, (int, float)):
		return struct.pack(float_format(size), value)
	if (dtype.is_integral() or dtype.is_enum() or dtype.is_bool()) and isinstance(value, int):
		return integer_bytes(value, size * 8)
	raise TypeError(f'cannot store {value!r} in {dtype}')

def integer_bytes(value: int, bits: int) -> bytes:
	''' An integer as `bits // 8` bytes. It may be given signed or unsigned. Raises `ValueError` when it does not fit. '''
	return check_range(value, bits).to_bytes(bits // 8, byte_order())

def check_range(value: int, bits: int) -> int:
	''' `value` as an unsigned integer of `bits` bits. Raises `ValueError` when it fits neither signed nor unsigned. '''
	if not -(1 << (bits - 1)) <= value < (1 << bits):
		raise ValueError(f'{value} does not fit in {bits} bits')
	return value & ((1 << bits) - 1)

def bitfield_bytes(udm: 'ida_typeinf.udm_t', data: bytes, value: int) -> bytes:
	''' The bytes a bitfield touches, `data` with the bitfield set to `value`. '''
	if not isinstance(value, int):
		raise TypeError(f'a bitfield takes an int, not {value!r}')
	shift, mask = udm.offset % 8, (1 << udm.size) - 1
	bits = int.from_bytes(data, byte_order()) & ~(mask << shift) | check_range(value, udm.size) << shift
	return bits.to_bytes(len(data), byte_order())

# PARSING

def parse_c(source: str, flags: int, what: str):
	''' Parse C declarations, or a header file with `HTI_FIL`, into the local types. Raises `IDAError` on an error, IDA keeping what it could parse. '''
	flags |= ida_typeinf.HTI_SEMICOLON
	errors = ida_typeinf.parse_decls(None, source, None, flags)
	compat.refresh_decompiler()
	if errors:
		raise IDAError(f'cannot parse {what}: {errors} error{"s" if errors > 1 else ""}{parser_messages(source, flags)}')

def parser_messages(source: str, flags: int) -> str:
	''' Parse again in test mode, printing IDA's messages, and return them.

	IDA prints them to the output window, which idalib does not have. A test run cannot use a struct an earlier declaration defined, so it comes after the real one.
	'''
	before = len(ida_kernwin.msg_get_lines(-1) or [])
	ida_typeinf.parse_decls(None, source, True, flags | ida_typeinf.HTI_TST)
	lines = ida_kernwin.msg_get_lines(-1) or []
	new = [line.strip() for line in reversed(lines[:len(lines) - before])]
	return ''.join(f'\n{line}' for line in new if line)

def defined_names(text: str) -> List[str]:
	''' Names of the structs and unions C declarations define, in order. An anonymous one counts by its typedef names. '''
	text = re.sub(r'/\*.*?\*/|//[^\n]*|^[ \t]*#[^\n]*', ' ', text, flags=re.S | re.M)
	names = []
	last = 0
	for match in re.finditer(r'[;{}]', text):
		head, last = text[last:match.start()], match.end()
		keyword = re.search(r'\b(?:struct|union)\b(.*)', head, re.S) if match.group() == '{' else None
		if not keyword:
			continue
		tag = identifiers(re.split(r'(?<!:):(?!:)', keyword.group(1))[0])
		if tag:
			names.append(tag[-1])
		elif re.search(r'\btypedef\b', head):
			names += identifiers(text[closing_brace(text, match.start()) + 1:].split(';', 1)[0])
	return list(dict.fromkeys(names))

def identifiers(text: str) -> List[str]:
	''' The identifiers in a piece of C, leaving out what is in parentheses (attributes). '''
	while re.search(r'\([^()]*\)', text):
		text = re.sub(r'\([^()]*\)', ' ', text)
	return re.findall(r'(?<![\w$])[A-Za-z_$][\w$]*(?:::[A-Za-z_$][\w$]*)*', text)

def closing_brace(text: str, start: int) -> int:
	''' Index of the brace closing the one at `start`. '''
	depth = 0
	for index in range(start, len(text)):
		if text[index] in '{}':
			depth += 1 if text[index] == '{' else -1
			if depth == 0:
				return index
	return len(text)
