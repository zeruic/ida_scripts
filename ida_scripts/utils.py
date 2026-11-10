from typing import *
import json
import operator

from . import compat

# THESE ARE INTERNAL UTILS
# -> not meant for the users

class IDAError(Exception):
	''' Base class of the errors this package raises. '''

class DecompileError(IDAError):
	''' The decompiler could not produce pseudocode. '''

class DebuggerError(IDAError):
	''' A debugger operation failed, or needed a process that is not there. '''

def to_ea(target: Any) -> int:
	''' Resolve anything that stands for an address to an integer.

	Parameters
	----------
	target : int, str, `Pointer`, `Func` or `Module`
		A `str` is a symbol name, or a hex literal starting with `0x`.

	Returns
	-------
	int
		The address.

	Raises
	------
	LookupError
		When a name is not in the database.
	'''
	if isinstance(target, bool):
		raise TypeError('a bool is not an address')
	if isinstance(target, int):
		return target
	if isinstance(target, str):
		text = target.strip()
		if text.lower().startswith('0x'):
			return int(text, 16)
		import ida_name
		ea = ida_name.get_name_ea(compat.BADADDR, text)
		if ea == compat.BADADDR:
			raise LookupError(f'no symbol named {text!r}')
		return ea
	for attribute in ('addr', 'start'):
		value = getattr(target, attribute, None)
		if isinstance(value, int):
			return value
	try:
		return operator.index(target)
	except TypeError:
		raise TypeError(f'{target!r} is not an address') from None

def jsonable(value: Any) -> Any:
	''' Convert a value to something `json.dumps` accepts. Addresses held by objects become hex strings. '''
	if value is None or isinstance(value, (bool, int, float, str)):
		return value
	if isinstance(value, (bytes, bytearray)):
		return bytes(value).hex()
	if hasattr(value, 'to_dict'):
		return value.to_dict()
	if isinstance(value, dict):
		return { str(k): jsonable(v) for k, v in value.items() }
	if isinstance(value, (list, tuple, set, frozenset)):
		return [jsonable(v) for v in value]
	if isinstance(getattr(value, 'addr', None), int):
		return hex(value.addr)
	return str(value)

def auto_repr(properties: List[str], transforms: Dict[str, Callable] = {}):
	''' Automatically generate __repr__ and to_dict from a list of properties, optionally specifying transforms. '''
	def decorator(cls):
		def transformed(self, p):
			value = getattr(self, p)
			return transforms[p](value) if p in transforms and value is not None else value
		def repr(self):
			props = ', '.join(f'{p}={transformed(self, p)}' for p in properties)
			return f'<{cls.__name__} {props}>'
		def to_dict(self) -> Dict[str, Any]:
			''' The main properties as a JSON-friendly `dict`, addresses as hex strings. '''
			return { p: jsonable(transformed(self, p)) for p in properties }
		cls.__repr__ = repr
		if 'to_dict' not in cls.__dict__:
			cls.to_dict = to_dict
		return cls
	return decorator

def hexdump(data, length = 16, sep = '.', start_offset = 0):
	result = []

	for i in range(0, len(data), length):
		subSrc = data[i:i+length]
		hexa = ''
		for h in range(0,len(subSrc)):
			if h == length/2:
				hexa += ' '
			h = subSrc[h]
			if not isinstance(h, int):
				h = ord(h)
			h = hex(h).replace('0x','')
			if len(h) == 1:
				h = '0'+h
			hexa += h+' '
		hexa = hexa.strip(' ')
		text = ''
		for c in subSrc:
			if not isinstance(c, int):
				c = ord(c)
			if 0x20 <= c < 0x7F:
				text += chr(c)
			else:
				text += sep
		result.append(('%08X:  %-'+str(length*(2+1)+1)+'s  |%s|') % (i + start_offset, hexa, text))

	return '\n'.join(result)

def to_hex(n: int) -> str:
	return hex(n)[2:].upper()

def get_properties(obj: object) -> Dict[str, Any]:
	attrs = {}
	for attr in dir(obj):
		try:
			val = getattr(obj, attr)
			if not callable(val):
				attrs[attr] = val
		except Exception as e:
			attrs[attr] = f'[Failed] {e}'
	return attrs

def print_properties(obj: object):
	print(json.dumps(get_properties(obj), indent=4, default=str))

pp = print_properties
