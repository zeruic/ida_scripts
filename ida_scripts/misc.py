''' Provides helper functions that work on the whole database: symbols, names, comments and strings, and annotations in bulk. '''

import re
from typing import *

from . import compat
from .compat import IN_IDA
from .utils import *
from .memory import Pointer, set_name
from .func import Func

if IN_IDA:
	import ida_bytes
	import ida_ida
	import ida_loader
	import ida_name
	import ida_nalt
	import ida_strlist
	import ida_typeinf
	import idautils

__all__ = ['find_symbol', 'search_names', 'search_comments', 'strings', 'StringRef', 'rename_all', 'comment_all', 'annotate_all', 'export_annotations', 'import_annotations']

# NAMES AND COMMENTS

def find_symbol(name: str) -> Optional[Pointer]:
	''' The address of a name, `None` when the database has no such name. A name that is not there is tried with a leading underscore, so `main` finds a Mach-O file's `_main`. '''
	ea = name_ea(name)
	return Pointer(ea) if ea is not None else None

def search_names(pattern: str, limit: int = None) -> List[Pointer]:
	''' The addresses whose name matches a regular expression, in address order.

	Parameters
	----------
	pattern : str
		Searched for anywhere in the name (`re.search`). Names IDA makes up on the fly, such as `sub_100000548` or `loc_100000550`, are not stored, so they never match.
	limit : int, default = None
		Stop after this many addresses.

	Returns
	-------
	list of `Pointer`
	'''
	regex = re.compile(pattern)
	found = []
	for ea, name in idautils.Names():
		if limit is not None and len(found) >= limit:
			break
		if regex.search(name):
			found.append(Pointer(ea))
	return found

def commented() -> Iterator[int]:
	''' Every address that has a regular or a repeatable comment, in address order. '''
	ea, end = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
	if not ida_bytes.has_cmt(ida_bytes.get_flags(ea)):
		ea = ida_bytes.next_that(ea, end, ida_bytes.has_cmt)
	while ea != compat.BADADDR and ea < end:
		if ida_bytes.get_cmt(ea, False) or ida_bytes.get_cmt(ea, True):
			yield ea
		ea = ida_bytes.next_that(ea, end, ida_bytes.has_cmt)

def comments_at(ea: int) -> List[str]:
	''' The regular and repeatable comments at an address, and the function comments when a function starts there. '''
	texts = [ida_bytes.get_cmt(ea, False), ida_bytes.get_cmt(ea, True)]
	if compat.func_start(ea) == ea:
		texts += [compat.func_comment(ea, False), compat.func_comment(ea, True)]
	return [text for text in texts if text]

def search_comments(pattern: str, limit: int = None, named_only: bool = True) -> List[Pointer]:
	''' The addresses whose comment matches a regular expression, in address order.

	Regular and repeatable comments count, and at the start of a function its function comments too.

	Parameters
	----------
	pattern : str
		Searched for anywhere in the comment (`re.search`).
	limit : int, default = None
		Stop after this many addresses.
	named_only : bool, default = True
		Look only at named addresses, which is fast. `False` looks at every address that has a comment, and every function.

	Returns
	-------
	list of `Pointer`
	'''
	regex = re.compile(pattern)
	if named_only:
		candidates = (ea for ea, _ in idautils.Names())
	else:
		candidates = sorted(set(commented()) | set(compat.func_starts()))
	found = []
	for ea in candidates:
		if limit is not None and len(found) >= limit:
			break
		if any(regex.search(text) for text in comments_at(ea)):
			found.append(Pointer(ea))
	return found

# STRINGS

@auto_repr(['address', 'text', 'funcs'], { 'funcs' : lambda funcs: [f.name for f in funcs] })
class StringRef:
	''' Represent one string of IDA's string list. '''

	def __init__(self, address: Union[int, Pointer], text: str):
		''' Init with the string's address and its text. '''
		self.address: Pointer = Pointer(address)
		''' Where the string starts. '''
		self.text: str = text
		''' The decoded string, without its terminator. '''

	@property
	def funcs(self) -> List[Func]:
		''' The functions that refer to the string, without duplicates and sorted by address. '''
		return sorted({ ref.func for ref in self.address.xrefs_to() if ref.func is not None }, key=lambda f: f.start)

	def __hash__(self) -> int:
		return hash((self.address.addr, self.text))

	def __eq__(self, o: object) -> bool:
		return type(o) is StringRef and (self.address, self.text) == (o.address, o.text)

STRING_LISTS: Dict[str, List[Tuple[int, int, int]]] = {}
''' The string list of each database `strings` has built, by database path: `(address, length, type)` of every string. '''

def string_list(refresh: bool) -> List[Tuple[int, int, int]]:
	''' `(address, length, type)` of every string of the database, built once and kept until `refresh`. '''
	path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
	if refresh or path not in STRING_LISTS:
		STRING_LISTS[path] = build_string_list()
	return STRING_LISTS[path]

def strings(pattern: str = None, encoding: str = None, refresh: bool = False) -> List[StringRef]:
	''' IDA's string list, C and UTF-16 strings, in address order.

	The list is built with the database's minimum length and with non-ASCII characters allowed, so it finds strings in the database's 8-bit encoding. The string list options are restored afterwards. Building takes seconds on a large database, so the list is kept for later calls.

	Parameters
	----------
	pattern : str, default = None
		Keep only the strings that match this regular expression (`re.search`).
	encoding : str, default = None
		Decode the bytes of the 8-bit strings with this Python encoding, such as `'cp932'`, instead of IDA's. UTF-16 strings stay UTF-16.
	refresh : bool, default = False
		Build the list again, after the database gained or lost strings.

	Returns
	-------
	list of `StringRef`
	'''
	regex = re.compile(pattern) if pattern is not None else None
	found = []
	for ea, length, strtype in string_list(refresh):
		if encoding and ida_nalt.get_strtype_bpu(strtype) == 1:
			text = Pointer(ea).read(length).split(b'\0', 1)[0].decode(encoding, 'backslashreplace')
		else:
			text = (ida_bytes.get_strlit_contents(ea, length, strtype) or b'').decode('utf-8', 'replace')
		if regex is None or regex.search(text):
			found.append(StringRef(ea, text))
	return found

def build_string_list() -> List[Tuple[int, int, int]]:
	''' Build IDA's string list with C and UTF-16 strings and return `(address, length, type)` of each, in address order. '''
	options = ida_strlist.get_strlist_options()
	saved = (options.strtypes, options.only_7bit)
	options.strtypes = [ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16]
	options.only_7bit = 0
	items = []
	try:
		ida_strlist.build_strlist()
		info = ida_strlist.string_info_t()
		for n in range(ida_strlist.get_strlist_qty()):
			if ida_strlist.get_strlist_item(info, n):
				items.append((info.ea, info.length, info.type))
	finally:
		options.strtypes, options.only_7bit = saved
		# The next user of the list, the Strings window for one, builds it again with the restored options.
		ida_strlist.clear_strlist()
	return sorted(items)

# BULK

def address(key: Any) -> int:
	''' An address from a key of an annotation `dict`. Also takes the decimal string JSON makes of an `int` key. '''
	if isinstance(key, str) and key.strip().isdigit():
		return int(key)
	return to_ea(key)

def annotate(items: Dict[Any, Tuple[Optional[str], Optional[str]]], force: bool, repeatable: bool) -> int:
	''' Set names and comments, refresh the decompiler once, and return how many addresses changed. '''
	resolved = [(address(key), name, comment) for key, (name, comment) in items.items()]
	changed = 0
	try:
		for ea, name, comment in resolved:
			done = False
			if name is not None and name != (ida_name.get_name(ea) or ''):
				done = set_name(ea, name, force)
			if comment is not None:
				if compat.func_start(ea) == ea:
					if comment != compat.func_comment(ea, repeatable):
						done = compat.set_func_comment(ea, comment, repeatable) or done
				elif comment != (ida_bytes.get_cmt(ea, repeatable) or ''):
					done = bool(ida_bytes.set_cmt(ea, comment, repeatable)) or done
			changed += bool(done)
	finally:
		compat.refresh_decompiler()
	return changed

def rename_all(names: Dict[int, str], force: bool = True) -> int:
	''' Name many addresses, refreshing the decompiler once at the end.

	Parameters
	----------
	names : dict
		`{address: name}`. An address is anything `Pointer` takes, or the decimal string JSON makes of an `int` key. Every address is resolved before anything changes.
	force : bool, default = True
		When a name is taken, let IDA use a numbered variant such as `name_0`.

	Returns
	-------
	int
		How many addresses changed name.
	'''
	return annotate({ key : (name, None) for key, name in names.items() }, force, True)

def comment_all(comments: Dict[int, str], repeatable: bool = True) -> int:
	''' Comment many addresses, refreshing the decompiler once at the end. A function's start gets a function comment, any other address an address comment.

	Parameters
	----------
	comments : dict
		`{address: comment}`, addresses as for `rename_all`. An empty comment removes the comment.
	repeatable : bool, default = True
		Set repeatable comments, which IDA also shows wherever the address is referenced, rather than regular ones.

	Returns
	-------
	int
		How many addresses changed comment.
	'''
	return annotate({ key : (None, comment) for key, comment in comments.items() }, True, repeatable)

def annotate_all(items: Dict[int, Tuple[Optional[str], Optional[str]]]) -> int:
	''' Name and comment many addresses, refreshing the decompiler once at the end.

	Names are set as `rename_all` does by default, with a numbered variant when a name is taken. Comments are repeatable, as `comment_all` sets them by default: a function comment at a function's start, an address comment anywhere else.

	Parameters
	----------
	items : dict
		`{address: (name, comment)}`, addresses as for `rename_all`. Either may be `None` to leave it as it is.

	Returns
	-------
	int
		How many addresses changed.
	'''
	return annotate(items, True, True)

# ANNOTATIONS

def local_types() -> List[str]:
	''' Every local type as a C declaration, each one after the types it needs. '''
	limit = ida_typeinf.get_ordinal_limit(None)
	ordinals = [n for n in range(1, limit) if ida_typeinf.get_numbered_type_name(None, n)]
	if not ordinals:
		return []
	class Sink(ida_typeinf.text_sink_t):
		def __init__(self):
			ida_typeinf.text_sink_t.__init__(self)
			self.parts = []
		def _print(self, text: str) -> int:
			self.parts.append(text)
			return 0
	sink = Sink()
	ida_typeinf.print_decls(sink, None, ordinals, ida_typeinf.PDF_INCL_DEPS | ida_typeinf.PDF_DEF_FWD)
	# Each type comes after a line with its ordinal, which another database numbers differently.
	pieces = re.split(r'^/\* \d+ \*/\n', ''.join(sink.parts), flags=re.M)
	return [piece.strip() for piece in pieces if piece.strip()]

def export_annotations() -> Dict[str, Any]:
	''' What people and scripts added to the database, for `import_annotations` to apply to another copy of the same binary.

	Returns
	-------
	dict
		JSON-friendly, addresses as hex strings:
		`names` (`{address: name}`, the names that IDA did not make up),
		`comments` and `repeatable_comments` (`{address: text}`),
		`function_comments` and `repeatable_function_comments` (`{function start: text}`),
		`prototypes` (`{function start: C prototype}`, the prototypes that were set rather than guessed),
		`types` (the local types as a list of C declarations, each after the types it needs).
	'''
	names = { hex(ea) : name for ea, name in idautils.Names() if ida_bytes.has_user_name(ida_bytes.get_flags(ea)) }
	comments, repeatable = {}, {}
	for ea in commented():
		for table, flag in ((comments, False), (repeatable, True)):
			text = ida_bytes.get_cmt(ea, flag)
			if text:
				table[hex(ea)] = text
	function_comments, repeatable_function_comments, prototypes = {}, {}, {}
	for start in compat.func_starts():
		for table, flag in ((function_comments, False), (repeatable_function_comments, True)):
			text = compat.func_comment(start, flag)
			if text:
				table[hex(start)] = text
		if ida_nalt.is_userti(start):
			prototype = ida_typeinf.print_type(start, ida_typeinf.PRTYPE_1LINE)
			if prototype:
				prototypes[hex(start)] = prototype
	return {
		'names' : names,
		'comments' : comments,
		'repeatable_comments' : repeatable,
		'function_comments' : function_comments,
		'repeatable_function_comments' : repeatable_function_comments,
		'prototypes' : prototypes,
		'types' : local_types(),
	}

def import_annotations(data: Dict[str, Any]) -> int:
	''' Apply what `export_annotations` returned, usually in another copy of the same binary. Refreshes the decompiler once at the end.

	Types come first, so that prototypes can use them. A name that another address already has is not applied. A prototype the function already has is left as it is.

	Parameters
	----------
	data : dict
		As `export_annotations` returns it, or as `json.loads` reads it back. Missing sections are skipped.

	Returns
	-------
	int
		How many entries the database holds afterwards, applied or already there: each name, comment, function comment, prototype and type counts once.
	'''
	applied = 0
	try:
		for declaration in data.get('types', []):
			applied += ida_typeinf.parse_decls(None, declaration, None, ida_typeinf.HTI_DCL) == 0
		for key, name in data.get('names', {}).items():
			applied += set_name(address(key), name)
		for section, flag in (('comments', False), ('repeatable_comments', True)):
			for key, text in data.get(section, {}).items():
				applied += bool(ida_bytes.set_cmt(address(key), text, flag))
		for section, flag in (('function_comments', False), ('repeatable_function_comments', True)):
			for key, text in data.get(section, {}).items():
				ea = address(key)
				applied += compat.func_start(ea) == ea and bool(compat.set_func_comment(ea, text, flag))
		for key, prototype in data.get('prototypes', {}).items():
			ea = address(key)
			# Parsing a printed prototype again can change it (a type library's __cdecl becomes __fastcall on ARM64), so an equal one stays.
			if ida_typeinf.print_type(ea, ida_typeinf.PRTYPE_1LINE) == prototype:
				applied += 1
				continue
			declaration = prototype.strip() if prototype.strip().endswith(';') else prototype.strip() + ';'
			applied += bool(ida_typeinf.apply_cdecl(None, ea, declaration, ida_typeinf.TINFO_DEFINITE))
	finally:
		compat.refresh_decompiler()
	return applied
