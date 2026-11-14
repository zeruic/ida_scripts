''' Provides class(es) for interacting with functions.

The module itself can be called as a shorthand, like `ptr`: `func('main')` is `Func('main')`.
'''

import hashlib
import os
import re
import sys
import types
from typing import *

from . import compat
from .compat import IN_IDA
from .utils import *
from .memory import Pointer, Xref, Insn, XREF_KINDS, disasm, set_name

if TYPE_CHECKING:
	from .struc import StrucT, MemberT

if IN_IDA:
	import ida_name
	import ida_nalt
	import ida_typeinf
	import ida_hexrays
	import ida_lines
	import ida_pro
	import ida_funcs
	import ida_bytes
	import ida_ua
	import idautils

__all__ = ['Func', 'CFunc', 'CItem', 'Call', 'export_fingerprints', 'match_functions', 'disasm']

def networkx():
	''' The `networkx` module, needed only for the tree of a decompiled function. '''
	try:
		import networkx
	except ImportError:
		raise IDAError('the tree of a decompiled function needs the networkx package') from None
	return networkx

@auto_repr(['op', 'address'], { 'id' : hex, 'address' : hex })
class CItem:
	''' Represent an item inside a graph of a decompiled function. '''

	def __init__(self, item: 'ida_hexrays.citem_t', graph: 'networkx.DiGraph'):
		''' Initialise with a `ida_hexrays.citem_t` object. '''
		self.item = item
		# python can handle retain cycles
		self.graph = graph

	@property
	def id(self) -> int:
		''' Item object id. '''
		return self.item.obj_id

	@property
	def address(self) -> int:
		''' Item address. '''
		return self.item.ea

	@property
	def op(self) -> str:
		''' Name of the operation represented by this item. '''
		return ida_hexrays.get_ctype_name(self.op_id)

	@property
	def op_id(self) -> int:
		''' The operation represented by this item. '''
		return self.item.op

	@property
	def type_name(self) -> str:
		''' The name of the type associated with this item. '''
		expr: ida_hexrays.cexpr_t = self.item.cexpr
		if self.item.is_expr() and not expr.type.empty():
			tstr = expr.type._print()
			return tstr

	@property
	def accessed_struct(self) -> 'StrucT':
		''' Find and return the `StrucT` accessed by this memptr/memref operation. '''
		from .struc import StrucT
		assert self.op_id in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref], 'Op is not memptr or memref.'
		if self.op_id == ida_hexrays.cot_memptr:
			struct_tinfo = self.item.cexpr.x.type.get_pointed_object()
		elif self.op_id == ida_hexrays.cot_memref:
			struct_tinfo = self.item.cexpr.x.type
		# IDA 9 prints a struct type as 'struct Player', its name is 'Player'.
		return StrucT.find(struct_tinfo.get_type_name() or str(struct_tinfo))

	@property
	def accessed_struct_member(self) -> 'MemberT':
		''' Find and return the `MemberT` accessed by this memptr/memref operation. '''
		assert self.op_id in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref], 'Op is not memptr or memref.'
		struct = self.accessed_struct
		member_offset = self.item.cexpr.m
		return struct.member_at_offset(member_offset)

	@property
	def called_function(self) -> 'Func':
		''' Find and return the `Func` called by this call operation. '''
		assert self.op_id in [ida_hexrays.cot_call], 'Op is not call!'
		return Func.func_at(self.item.x.obj_ea)

	@property
	def num_value(self) -> int:
		''' Return the value corresponding to this num operation. '''
		assert self.op_id in [ida_hexrays.cot_num], 'Op is not num!'
		return self.item.n._value

	# @property
	# def is_member_defined_in_struct(self) -> bool:
	# 	''' Checks whether there exists a member in the referenced struct type starting at the offset. '''
	# 	return self.accessed_struct.member_starting_at_offset(self.item.cexpr.m) is not None

	@property
	def label(self) -> str:
		''' Short label for item. '''
	
		def get_expr_name(expr):
			name = expr.print1(None)
			name = ida_lines.tag_remove(name)
			name = ida_pro.str2user(name)
			return name
		
		op = self.item.op
		insn = self.item.cinsn
		expr = self.item.cexpr
		parts = [ida_hexrays.get_ctype_name(op)]
		if op == ida_hexrays.cot_ptr:
			parts.append(".%d" % expr.ptrsize)
		elif op == ida_hexrays.cot_memptr:
			parts.append(".%d (m=%d)" % (expr.ptrsize, expr.m))
		elif op == ida_hexrays.cot_memref:
			parts.append(" (m=%d)" % (expr.m,))
		elif op in [
				ida_hexrays.cot_obj,
				ida_hexrays.cot_var]:
			name = get_expr_name(expr)
			parts.append(".%d %s" % (expr.refwidth, name))
		elif op in [
				ida_hexrays.cot_num,
				ida_hexrays.cot_helper,
				ida_hexrays.cot_str]:
			name = get_expr_name(expr)
			parts.append(" %s" % (name,))
		elif op == ida_hexrays.cit_goto:
			parts.append(" LABEL_%d" % insn.cgoto.label_num)
		elif op == ida_hexrays.cit_asm:
			parts.append("<asm statements; unsupported ATM>")
		if self.item.is_expr() and not expr.type.empty():
			tstr = expr.type._print()
			parts.append(tstr if tstr else "?")
		return "//".join(parts)

	@property
	def children(self) -> List['CItem']:
		''' The children of this item. '''
		return list(self.graph.successors(self))
	
	@property
	def n_children(self) -> int:
		''' The number of children of this item. '''
		return len(self.children)

	@property
	def parent(self) -> 'CItem':
		''' The parent of this item. '''
		try:
			return next(self.graph.predecessors(self))
		except:
			return None

	@property
	def parent_expression(self) -> 'CItem':
		''' Find and return the parent expression. '''
		return self.parent_where(lambda parent: parent.op_id == ida_hexrays.cit_expr)

	def child_where(self, condition: Callable[['CItem'], bool]) -> 'CItem':
		''' Preorder dfs search for the first child meeting the condition. '''
		dfs = networkx().dfs_preorder_nodes(self.graph, self)
		node = next(dfs)
		while node:
			if condition(node):
				return node
			try:
				node = next(dfs)
			except:
				break

	def children_where(self, condition: Callable[['CItem'], bool]) -> List['CItem']:
		''' Preorder dfs search for all children meeting the condition. '''
		dfs = networkx().dfs_preorder_nodes(self.graph, self)
		nodes = []
		node = next(dfs)
		while node:
			if condition(node):
				nodes.append(node)
			try:
				node = next(dfs)
			except:
				break
		return nodes

	def parent_where(self, condition: Callable[['CItem'], bool]) -> 'CItem':
		''' Walk up the parents for the first one meeting the condition. '''
		parent = self.parent
		while parent:
			if condition(parent):
				return parent
			parent = parent.parent

	def subtree_search_strict(self, query: Dict[str, Any]) -> List[List[List['CItem']]]:
		''' Perform a dfs tree search with the specified query.
		
		The query is a `dict` representing a subtree to search for, recursively defined as:
		```
		<query> = {
			"op" : <str>,
			"condition" : <lambda (CItem) -> bool>,
			"children" : [<query>, ...]
		}
		```

		`op` the name of the operation for the current item
		`condition` the matching condition for the current item
		`children` nested query(ies) specifying the children to match

		All fields are optional, but at least one of `op, condition` must be present.
		The query does not have to specify the complete subtree, but each of its specified level must be complete.
		ie. If node A has children B, C, query can either not specify A's children at all or it must specify A's children as both B and C.

		Returns results as a list of `List[List[CItem]]`, the outermost list representing the unique matches, each inner `List[List[CItem]]` representing a match.
		Example of a match:

		Query: `{ op : A, children: [{ op : B}, { op : C }]}`

		A Match: `[[A], [B, C]]`

		Returns: `[[[A], [B, C]], ...]`

		'''

		results = []

		def recursive_search(item: CItem, query: Dict[str, Any], result: List[List[CItem]] = None, index: int = 0) -> bool:
			assert 'condition' in query or 'op' in query, 'Query must have at least one of condition or op!'
			nonlocal results

			if index == 0:
				result = [[]]

			match = True
			# 1. check each of the other attributes
			attrs = { 'op' }
			for attr in attrs:
				if attr in query:
					match = match and query[attr] == getattr(item, attr)
			# 2. check condition, if exists
			if match and 'condition' in query:
				match = match and query['condition'](item)

			# always try to match deeper subtrees
			if index == 0:
				for child in item.children:
					recursive_search(child, query, None, 0)

			if match:
				# this node matches, search subtree
				subtree_match = False
				# add this item to the appropriate position
				if index == len(result):
					result.append([item])
				else:
					result[index].append(item)
				# this item matches, try to match children 'strictly'
				if item.n_children == 0 or not 'children' in query:
					# reached end of search
					# success if query has on more children
					subtree_match = not 'children' in query
				else:
					# needs to search deeper
					children = item.children
					if len(children) == len(query['children']):					
						for child_query in query['children']:
							for child_item in item.children:
								if recursive_search(child_item, child_query, result, index+1):
									children.remove(child_item)
									break

						if len(children) == 0:
							# queries 1-1 matched
							subtree_match = True
				if subtree_match and index == 0:
					results.append(result)
				return subtree_match
			
			# else this node doesn't match
			return False

		recursive_search(self, query)
		return results

	def __hash__(self):
		return self.item.obj_id

	def __eq__(self, other: 'CItem'):
		return hash(self) == hash(other)

if IN_IDA:
	class GraphBuilder(ida_hexrays.ctree_parentee_t):
		''' Utility class used to build the decompiled items graph. '''

		def __init__(self):
			ida_hexrays.ctree_parentee_t.__init__(self)
			self.graph = networkx().DiGraph()

		def add_item(self, item: 'ida_hexrays.citem_t', type: str):
			parent = self.parents.back()
			item = CItem(item, self.graph)
			self.graph.add_node(item, type=type)
			if parent:
				self.graph.add_edge(CItem(parent, self.graph), item)
			return 0

		def visit_insn(self, i: 'ida_hexrays.cinsn_t'):
			return self.add_item(i, 'insn')

		def visit_expr(self, e: 'ida_hexrays.cexpr_t'):
			return self.add_item(e, 'expr')

@auto_repr(['original'])
class CFunc:
	''' Represent a decompiled function. '''

	def __init__(self, original: 'Func', decompiled: 'ida_hexrays.cfunc_t'):
		''' Initialise with the original `Func` and the decompiled `ida_hexrays.cfunc_t` object. '''
		self.original = original
		''' The `Func` object from which this object is derived. '''
		self.decompiled = decompiled
		''' The decompiled `ida_hexrays.cfunc_t` object. '''
		self.graph = None

	@property
	def body(self) -> 'networkx.DiGraph':
		''' The graph representing the decompiled function, each node a `CItem`. Built on first use, needs `networkx`. '''
		if self.graph is None:
			gb = GraphBuilder()
			gb.apply_to(self.decompiled.body, None)
			# The items point into the decompiled function, so the graph keeps it alive after the decompiler drops it from its cache.
			gb.graph.graph['cfunc'] = self.decompiled
			self.graph = gb.graph
		return self.graph

	@property
	def body_root(self) -> CItem:
		''' The root node of the graph for this function. '''
		return next(networkx().topological_sort(self.body))

	@property
	def lines(self) -> List[str]:
		''' The pseudocode, one string per line. '''
		return [ida_lines.tag_remove(line.line) for line in self.decompiled.get_pseudocode()]

	@property
	def pseudocode(self) -> str:
		''' Pseudocode of the decompiled function. '''
		return '\n'.join(self.lines)

	psuedocode = pseudocode
	''' The old, misspelt name of `CFunc.pseudocode`. '''

	def _declarations(self, lines: List[str]) -> range:
		''' Where `lines`, just taken from `CFunc.lines`, declare the local variables: the lines after the opening brace, and the blank line after them. Empty when there are none. '''
		header = min(self.decompiled.hdrlines, len(lines))
		brace = next((n for n in range(header - 1, -1, -1) if lines[n] == '{'), None)
		if brace is None or brace + 1 >= header:
			return range(0)
		end = header + 1 if header < len(lines) and lines[header] == '' else header
		return range(brace + 1, end)

	def text(self, decls: bool = True, max_lines: int = None, shorten: int = None) -> str:
		''' The pseudocode, optionally made shorter.

		Parameters
		----------
		decls : bool, default = True
			`False` leaves out the declarations of the local variables at the top of the body, and the blank line after them.
		max_lines : int, default = None
			Keep only the first `max_lines` lines, then a line `// … N more lines` saying how many were cut.
		shorten : int, default = None
			Cut every identifier longer than `shorten` characters to its first `shorten` characters followed by `…`. String literals and comments stay as they are.

		Returns
		-------
		str
			The text, lines separated by `\\n`.
		'''
		if max_lines is not None and max_lines < 0:
			raise ValueError(f'max_lines must be 0 or more, not {max_lines}')
		if shorten is not None and shorten < 1:
			raise ValueError(f'shorten must be 1 or more, not {shorten}')
		lines = self.lines
		if not decls:
			skipped = self._declarations(lines)
			lines = [line for n, line in enumerate(lines) if n not in skipped]
		if shorten is not None:
			lines = [shorten_identifiers(line, shorten) for line in lines]
		if max_lines is not None and len(lines) > max_lines:
			lines = lines[:max_lines] + [f'// … {len(lines) - max_lines} more lines']
		return '\n'.join(lines)

	def grep(self, pattern: str, context: int = 2) -> str:
		''' The pseudocode lines that match a regular expression, with the lines around them.

		Parameters
		----------
		pattern : str
			Searched for anywhere in a line (`re.search`).
		context : int, default = 2
			How many lines to show before and after each match.

		Returns
		-------
		str
			Numbered lines in the style of `grep -n`: `12:text` for a match, `11-text` around it, `--` between groups that are not next to each other. `''` when nothing matches.
		'''
		regex = re.compile(pattern)
		lines = self.lines
		matches = { n for n, line in enumerate(lines) if regex.search(line) }
		shown = sorted({ n for match in matches for n in range(max(0, match - context), min(len(lines), match + context + 1)) })
		result = []
		for n in shown:
			if result and n != previous + 1:
				result.append('--')
			result.append(f'{n + 1}{":" if n in matches else "-"}{lines[n]}')
			previous = n
		return '\n'.join(result)

	def save(self, path: str) -> str:
		''' Write the pseudocode to a file, replacing what it holds. Returns the file's absolute path. '''
		path = os.path.abspath(os.path.expanduser(path))
		with open(path, 'w', encoding='utf-8') as file:
			file.write(self.pseudocode + '\n')
		return path

# A string or character literal, a comment, or an identifier.
TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|//.*|/\*.*?\*/|\b[A-Za-z_]\w*')

def shorten_identifiers(line: str, limit: int) -> str:
	''' Cut every identifier in a line of C longer than `limit` characters to `limit` characters followed by `…`. Literals and comments stay as they are. '''
	def replace(match: 're.Match') -> str:
		token = match.group(0)
		if token[0] in '"\'/' or len(token) <= limit:
			return token
		return token[:limit] + '…'
	return TOKEN.sub(replace, line)

@auto_repr(['site', 'kind', 'target', 'text'], { 'site' : hex, 'target' : lambda f: hex(f.start) })
class Call:
	''' Represent one call that a function makes. '''

	def __init__(self, site: int, kind: str, target: Optional['Func'], text: str):
		''' Init with the calling instruction's address, the kind of call, the called function and its text. '''
		self.site: int = site
		''' Address of the calling instruction. '''
		self.kind: str = kind
		''' `'direct'`: a call instruction with a code reference. `'tail'`: a jump to the start of another function. `'indirect'`: a call instruction without a code reference, through a register or memory. '''
		self.target: Optional[Func] = target
		''' The called function. `None` for an indirect call, or a target that is in no function. '''
		self.text: str = text
		''' The target's name (its address when it has none), or the operand of an indirect call such as `'X8'`. '''

	def __hash__(self) -> int:
		return hash((self.site, self.kind, self.text))

	def __eq__(self, o: object) -> bool:
		return type(o) is Call and (self.site, self.kind, self.target, self.text) == (o.site, o.kind, o.target, o.text)

def code_heads(chunks: List[Tuple[int, int]]) -> Iterator[int]:
	''' Address of every instruction in the chunks, in order. '''
	for start, end in chunks:
		ea = start
		while ea < end and ea != compat.BADADDR:
			if ida_bytes.is_code(ida_bytes.get_flags(ea)):
				yield ea
			ea = ida_bytes.next_head(ea, end)

def fingerprint_at(start: int) -> str:
	''' `Func.fingerprint` of the function starting at `start`. '''
	mnemonics = ' '.join(ida_ua.print_insn_mnem(ea) or '' for ea in code_heads(compat.func_chunks(start)))
	return hashlib.sha256(mnemonics.encode()).hexdigest()

@auto_repr(['name', 'start', 'end', 'size'], { 'start' : hex, 'end' : hex, 'size' : hex})
class Func:
	''' Represent a function. '''

	@staticmethod
	def find(name: str) -> Optional['Func']:
		''' Find function by name, `None` when there is none. A name that is not there is tried with a leading underscore, so `main` finds a Mach-O file's `_main`. '''
		ea = name_ea(name)
		return Func(ea) if ea is not None and compat.func_start(ea) == ea else None

	@staticmethod
	def at(addr: Union[int, str, Pointer]) -> Optional['Func']:
		''' The function containing an address, `None` when it is in no function. '''
		start = compat.func_start(to_ea(addr))
		return Func(start) if start is not None else None

	func_at = at
	''' The old name of `Func.at`. '''

	@staticmethod
	def search(pattern: str, limit: int = None) -> List['Func']:
		''' The functions whose name matches a regular expression, in address order.

		Parameters
		----------
		pattern : str
			Searched for anywhere in the name (`re.search`), anchor it to match the whole name.
		limit : int, default = None
			Stop after this many functions.

		Returns
		-------
		list of `Func`
		'''
		regex = re.compile(pattern)
		found = []
		for start in compat.func_starts():
			if limit is not None and len(found) >= limit:
				break
			if regex.search(ida_name.get_name(start) or ''):
				found.append(Func(start))
		return found

	@staticmethod
	def all() -> Iterator['Func']:
		''' Every function, in address order. '''
		return (Func(start) for start in compat.func_starts())

	ignore: Set[str] = set()
	''' Regular expressions of callee names that `Func.callees` and `Func.calls` leave out, such as runtime helpers that drown the list. Searched for anywhere in the name (`re.search`). Empty by default. '''

	def __init__(self, target: Union[int, str, Pointer, 'Func']):
		''' Initialise with any address inside the function, or its name. Raises `LookupError` when there is no function. '''
		ea = target.start_ea if hasattr(target, 'start_ea') else to_ea(target)
		start = compat.func_start(ea)
		if start is None:
			raise LookupError(f'no function at {hex(ea)}')
		self.start: int = start
		''' Function start address. '''

	@property
	def name(self) -> str:
		''' Function name. Assign to rename. '''
		return ida_name.get_name(self.start) or ''

	@name.setter
	def name(self, name: str):
		if not self.rename(name):
			raise IDAError(f'cannot name {hex(self.start)} {name!r}')

	def rename(self, name: str, force: bool = False) -> bool:
		''' Rename the function. With `force`, IDA may use a numbered variant when the name is taken. '''
		done = set_name(self.start, name, force)
		if done:
			compat.refresh_decompiler()
		return done

	@property
	def end(self) -> int:
		''' End address of the function's first chunk. '''
		return compat.func_end(self.start)

	@property
	def size(self) -> int:
		''' Function size in bytes, all chunks together. '''
		return compat.func_size(self.start)

	@property
	def chunks(self) -> List[Tuple[int, int]]:
		''' Every chunk of the function as `(start, end)`, in address order. More than one when the function has tails. '''
		return compat.func_chunks(self.start)

	def contains(self, addr: Union[int, str, Pointer]) -> bool:
		''' Whether an address lies in any chunk of this function. '''
		ea = to_ea(addr)
		return any(start <= ea < end for start, end in self.chunks)

	@property
	def tif(self) -> Optional['ida_typeinf.tinfo_t']:
		''' Type of the function, `None` when it has none. '''
		tif = ida_typeinf.tinfo_t()
		return tif if ida_nalt.get_tinfo(tif, self.start) else None

	@property
	def arguments(self) -> Dict[str, 'ida_typeinf.tinfo_t']:
		''' Return a `dict` of argument name to type info. '''
		tif = self.tif
		func_data = ida_typeinf.func_type_data_t()
		if not tif or not tif.get_func_details(func_data):
			return {}
		# Copies: an argument's own type belongs to func_data and goes with it.
		return { arg.name : arg.type.copy() for arg in func_data }

	@property
	def comment(self) -> str:
		''' The function comment, repeated wherever the function is referenced. `''` when there is none. Assign to set it. '''
		return compat.func_comment(self.start)

	@comment.setter
	def comment(self, text: str):
		if not compat.set_func_comment(self.start, text):
			raise IDAError(f'cannot comment {self.name or hex(self.start)}')
		compat.refresh_decompiler(self.start)

	@property
	def prototype(self) -> str:
		''' The function's C prototype, `''` when it has no type. Assign a C declaration to set it. '''
		return ida_typeinf.print_type(self.start, ida_typeinf.PRTYPE_1LINE) or ''

	@prototype.setter
	def prototype(self, declaration: str):
		if not self.set_prototype(declaration):
			raise IDAError(f'cannot apply {declaration!r} to {self.name or hex(self.start)}')

	def set_prototype(self, declaration: str) -> bool:
		''' Apply a C prototype such as `int __fastcall add(int a, int b)`. Returns whether IDA accepted it. '''
		done = set_prototype(self.start, declaration)
		if done:
			compat.refresh_decompiler()
		return done

	def decompile(self) -> CFunc:
		''' Decompile this function. Raises `DecompileError` when the decompiler fails. '''
		cfunc, reason = compat.decompile(self.start)
		if not cfunc:
			raise DecompileError(f'cannot decompile {self.name or hex(self.start)}: {reason}')
		return CFunc(self, cfunc)

	def pseudocode(self, **options) -> str:
		''' The decompiled function as text: `decompile().text(**options)`, see `CFunc.text` for the options. Raises `DecompileError` when the decompiler fails. '''
		return self.decompile().text(**options)

	def disasm(self) -> str:
		''' The function's disassembly, one instruction per line after its address, every chunk in address order with a blank line between chunks. '''
		return '\n\n'.join('\n'.join(f'{hex(insn.address)}  {insn.text}' for insn in disasm(start, end)) for start, end in self.chunks)

	def call(self, *args) -> Any:
		''' Call this function in the debugged process with its prototype, through `Debugger.call`, and return its result.

		Raises `IDAError` when the function has no prototype: set `Func.prototype` first.
		'''
		prototype = self.prototype
		if not prototype:
			raise IDAError(f'cannot call {self.name or hex(self.start)}: it has no prototype, set Func.prototype first')
		from .debugger import dbg
		return dbg.call(self.start, prototype, *args)

	# CODE
	@property
	def is_thunk(self) -> bool:
		''' Whether IDA marks this function as a thunk, a function that only jumps to another one, such as an import stub. '''
		return bool(compat.func_flags(self.start) & ida_funcs.FUNC_THUNK)

	@property
	def thunk_target(self) -> Optional['Func']:
		''' The function a thunk jumps to. `None` when this is not a thunk, or when the target is in no function of the database, as for an import. '''
		target = compat.thunk_target(self.start)
		return Func.at(target) if target is not None else None

	@property
	def insns(self) -> List[Insn]:
		''' Every instruction, all chunks in address order. '''
		return [insn for start, end in self.chunks for insn in disasm(start, end)]

	@property
	def fingerprint(self) -> str:
		''' SHA-256 (hex) of the sequence of mnemonics, all chunks in address order. It does not depend on addresses, so the same code has the same fingerprint in another build. '''
		return fingerprint_at(self.start)

	@property
	def calls(self) -> List[Call]:
		''' The calls this function makes, in address order. Calls to a name that matches `Func.ignore` are left out.

		A call instruction with a code reference is a `'direct'` call, one without (`BLR X8`, `call [eax+8]`) an `'indirect'` call. A jump to the start of another function, from inside this one to outside its chunks, is a `'tail'` call. A jump inside this function is not a call.
		'''
		chunks = self.chunks
		ignore = [re.compile(pattern) for pattern in Func.ignore]
		calls = []
		for insn in self.insns:
			targets = [(XREF_KINDS[x.type], x.to) for x in idautils.XrefsFrom(insn.address, 0) if XREF_KINDS.get(x.type) in ('call', 'jump')]
			if insn.is_call:
				found = [('direct', to) for kind, to in targets if kind == 'call']
				if not found:
					calls.append(Call(insn.address, 'indirect', None, ', '.join(insn.ops)))
			else:
				found = [('tail', to) for kind, to in targets if kind == 'jump' and compat.func_start(to) == to and not any(start <= to < end for start, end in chunks)]
			for kind, to in found:
				text = ida_name.get_name(to) or hex(to)
				if not any(regex.search(text) for regex in ignore):
					calls.append(Call(insn.address, kind, Func.at(to), text))
		return calls

	@property
	def callees(self) -> List['Func']:
		''' The functions this one calls, directly or as a tail call, without duplicates and sorted by address. Names that match `Func.ignore` are left out. '''
		return sorted({ call.target for call in self.calls if call.target is not None }, key=lambda f: f.start)

	@property
	def callers(self) -> List['Func']:
		''' The functions that call this one, directly or as a tail call, without duplicates and sorted by address. '''
		callers = set()
		for ref in self.xrefs_to:
			caller = ref.func
			if caller is None:
				continue
			if ref.kind == 'call' or (ref.kind == 'jump' and not self.contains(ref.frm)):
				callers.add(caller)
		return sorted(callers, key=lambda f: f.start)

	@property
	def xrefs_to(self) -> List[Xref]:
		''' The references to the function's start, ordinary flow left out. '''
		return Pointer(self.start).xrefs_to()

	@property
	def data_refs(self) -> List[Pointer]:
		''' The addresses the function refers to as data, without duplicates and sorted: the globals it reads and writes, and the addresses it takes, such as a string's or a function's. '''
		refs = set()
		for start, end in self.chunks:
			for ea in idautils.Heads(start, end):
				refs.update(idautils.DataRefsFrom(ea))
		return [Pointer(ea) for ea in sorted(refs)]

	@property
	def strings(self) -> List[Tuple[Pointer, str]]:
		''' The string literals the function refers to, as `(address, text)` sorted by address. Only strings that the database defines count. '''
		found = []
		for ref in self.data_refs:
			if ida_bytes.is_strlit(ida_bytes.get_flags(ref.addr)):
				data = ida_bytes.get_strlit_contents(ref.addr, ida_bytes.get_item_size(ref.addr), ida_nalt.get_str_type(ref.addr)) or b''
				found.append((ref, data.decode('utf-8', 'replace')))
		return found

	def __hash__(self) -> int:
		return self.start

	def __eq__(self, o: object) -> bool:
		return type(o) is Func and self.start == o.start

def set_prototype(ea: int, declaration: str) -> bool:
	''' Apply a C prototype to an address without refreshing the decompiler. Bulk changes call this, then refresh once. '''
	declaration = declaration.strip()
	if not declaration.endswith(';'):
		declaration += ';'
	return bool(ida_typeinf.apply_cdecl(None, ea, declaration, ida_typeinf.TINFO_DEFINITE))

def fingerprint_groups() -> Dict[str, List[int]]:
	''' The start of every function, grouped by fingerprint. '''
	groups = {}
	for start in compat.func_starts():
		groups.setdefault(fingerprint_at(start), []).append(start)
	return groups

def export_fingerprints(named_only: bool = True) -> Dict[str, str]:
	''' Fingerprints and names of the functions of this database, to find them in another build with `match_functions`.

	Parameters
	----------
	named_only : bool, default = True
		Leave out the functions that only have a name IDA made up, such as `sub_100000548`.

	Returns
	-------
	dict
		`{fingerprint: name}` for every function whose fingerprint no other function here has. JSON-friendly.
	'''
	result = {}
	for fingerprint, starts in fingerprint_groups().items():
		if len(starts) == 1 and (not named_only or ida_bytes.has_name(ida_bytes.get_flags(starts[0]))):
			result[fingerprint] = ida_name.get_name(starts[0])
	return result

def match_functions(fingerprints: Dict[str, str]) -> Dict[int, str]:
	''' Find the functions of another build in this database, by fingerprint.

	Parameters
	----------
	fingerprints : dict
		`{fingerprint: name}`, from `export_fingerprints` in the other database.

	Returns
	-------
	dict
		`{start address here: name there}` for every function whose fingerprint is in `fingerprints` and belongs to no other function here. `misc.rename_all` applies it.
	'''
	return { starts[0] : fingerprints[fingerprint] for fingerprint, starts in fingerprint_groups().items() if len(starts) == 1 and fingerprint in fingerprints }


class CallableModule(types.ModuleType):
	''' Lets this module be called, so `func` names both the module and the shorthand without one hiding the other. '''

	def __call__(self, target: Union[int, str, Pointer, Func]) -> Func:
		''' Initialise a `Func`. '''
		return Func(target)

sys.modules[__name__].__class__ = CallableModule
