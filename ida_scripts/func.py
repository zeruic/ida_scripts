''' Provides class(es) for interacting with functions.

The module itself can be called as a shorthand, like `ptr`: `func('main')` is `Func('main')`.
'''

import collections.abc
import hashlib
import json
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
	import ida_netnode
	import ida_typeinf
	import ida_hexrays
	import ida_lines
	import ida_pro
	import ida_funcs
	import ida_bytes
	import ida_ua
	import ida_xref
	import idautils

__all__ = ['Func', 'CFunc', 'CItem', 'Call', 'grep', 'show_code', 'export_fingerprints', 'match_functions', 'disasm']

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
		return Func.at(self.item.x.obj_ea)

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

	class CallCollector(ida_hexrays.ctree_visitor_t):
		''' Utility class used to collect the calls of a decompiled function. '''

		def __init__(self):
			ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
			self.calls = []

		def visit_expr(self, e: 'ida_hexrays.cexpr_t'):
			# A helper such as LODWORD(x) is printed as a call, and is none.
			if e.op == ida_hexrays.cot_call and e.x.op != ida_hexrays.cot_helper:
				callee = e.x.obj_ea if e.x.op == ida_hexrays.cot_obj else None
				if callee is not None and compat.func_start(callee) == callee:
					target, kind, text = Func(callee), 'direct', ida_name.get_name(callee) or hex(callee)
				else:
					target, kind, text = None, 'indirect', expression_text(e.x)
				self.calls.append(Call(e.ea, kind, target, text, [expression_text(arg) for arg in e.a]))
			return 0

	# In a tagged pseudocode line: the anchor of an item, then its text inside one colour.
	ANCHORED_TEXT = re.compile(re.escape(ida_lines.SCOLOR_ON + ida_lines.SCOLOR_ADDR) + r'([0-9A-Fa-f]{%d})' % ida_lines.COLOR_ADDR_SIZE + re.escape(ida_lines.SCOLOR_ON) + r'(.)([^\x01\x02]+)' + re.escape(ida_lines.SCOLOR_OFF) + r'\2', re.S)

def expression_text(expression: 'ida_hexrays.cexpr_t') -> str:
	''' An expression of a decompiled function as the pseudocode has it. '''
	return ida_lines.tag_remove(expression.print1(None))

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

	def _calls(self) -> List['Call']:
		''' Every call in the pseudocode, in address order. '''
		collector = CallCollector()
		collector.apply_to(self.decompiled.body, None)
		return sorted(collector.calls, key=lambda call: call.site)

	@property
	def calls(self) -> List['Call']:
		''' The calls in the pseudocode with their arguments, in address order. Calls to a name that matches `Func.ignore` are left out.

		Each `Call` has `args`, the arguments as the pseudocode has them. A call to a function is `'direct'`, with the function's name as its `text`. Any other is `'indirect'`, with the expression that is called as its `text`. What the decompiler prints as a call and is none, such as `LODWORD(x)`, is left out.
		'''
		ignore = [re.compile(pattern) for pattern in Func.ignore]
		return [call for call in self._calls() if call.target is None or not any(regex.search(call.text) for regex in ignore)]

	def _ignored_names(self) -> Set[str]:
		''' How the pseudocode spells the functions that match `Func.ignore`. It can spell a name differently from IDA: `_add` is `add` there, and a character C does not allow is `_`. '''
		ignore = [re.compile(pattern) for pattern in Func.ignore]
		if not ignore:
			return set()
		# The items are numbered once the pseudocode is printed.
		lines = self.decompiled.get_pseudocode()
		items = self.decompiled.treeitems
		names = set()
		for line in lines:
			for anchor, _, text in ANCHORED_TEXT.findall(line.line):
				anchor = int(anchor, 16)
				index = anchor & ida_hexrays.ANCHOR_INDEX
				if anchor & ida_hexrays.ANCHOR_MASK != ida_hexrays.ANCHOR_CITEM or index >= len(items):
					continue
				item = items[index]
				if item.op != ida_hexrays.cot_obj:
					continue
				ea = item.cexpr.obj_ea
				if compat.func_start(ea) == ea and any(regex.search(ida_name.get_name(ea) or hex(ea)) for regex in ignore):
					names.add(text)
		return names

	def _declarations(self, lines: List[str]) -> range:
		''' Where `lines`, just taken from `CFunc.lines`, declare the local variables: the lines after the opening brace, and the blank line after them. Empty when there are none. '''
		header = min(self.decompiled.hdrlines, len(lines))
		brace = next((n for n in range(header - 1, -1, -1) if lines[n] == '{'), None)
		if brace is None or brace + 1 >= header:
			return range(0)
		end = header + 1 if header < len(lines) and lines[header] == '' else header
		return range(brace + 1, end)

	def text(self, decls: bool = False, max_lines: int = None, shorten: int = None, start: int = 0, hide: Union[str, Iterable[str]] = None, ignore: bool = False) -> str:
		''' The pseudocode, without the declarations of its local variables. The options cut it to a window (`start`, `max_lines`), shorten long identifiers (`shorten`), and leave statements out (`hide` by a regular expression, `ignore` for the calls of functions in `Func.ignore`).

		A statement that `hide` or `ignore` takes out takes with it what it would leave empty: the `if` or `else` it was the whole body of, and a block with nothing left in it. Where that would change how the rest reads, as for the first branch of an `if` that has an `else`, or the body of a loop, the statement stays. A last line `// … N lines hidden` says how many lines went.

		Parameters
		----------
		decls : bool, default = False
			`True` keeps the declarations of the local variables at the top of the body, and the blank line after them.
		max_lines : int, default = None
			Keep only the first `max_lines` lines, then a line `// … N more lines` saying how many were cut.
		shorten : int, default = None
			Cut every identifier longer than `shorten` characters to its first `shorten` characters followed by `…`. String literals and comments stay as they are.
		start : int, default = 0
			Leave out the first `start` lines, with a line `// … N lines above` in their place. Together with `max_lines` this shows a window, such as what an earlier call cut off. The lines are counted after `decls`, `hide` and `ignore` took theirs out.
		hide : str or iterable of str, default = None
			Leave out every line that one of these regular expressions matches (`re.search`), as a whole statement, see below.
		ignore : bool, default = False
			Leave out the statements that only call a function matching `Func.ignore`, such as `init_once(&flag);`. A call whose result is used stays.

		Returns
		-------
		str
			The text, lines separated by `\\n`.
		'''
		if max_lines is not None and max_lines < 0:
			raise ValueError(f'max_lines must be 0 or more, not {max_lines}')
		if shorten is not None and shorten < 1:
			raise ValueError(f'shorten must be 1 or more, not {shorten}')
		if start < 0:
			raise ValueError(f'start must be 0 or more, not {start}')
		lines = self.lines
		if not decls:
			skipped = self._declarations(lines)
			lines = [line for n, line in enumerate(lines) if n not in skipped]
		patterns = [re.compile(pattern) for pattern in ([hide] if isinstance(hide, str) else hide or [])]
		names = self._ignored_names() if ignore else set()
		hidden = 0
		if patterns or names:
			lines, hidden = hide_lines(lines, patterns, names)
		if shorten is not None:
			lines = [shorten_identifiers(line, shorten) for line in lines]
		if start:
			above = min(start, len(lines))
			lines = [f'// … {above} line{"" if above == 1 else "s"} above'] + lines[start:]
		shown = len(lines) - bool(start)
		if max_lines is not None and shown > max_lines:
			lines = lines[:max_lines + bool(start)] + [f'// … {shown - max_lines} more lines']
		if hidden:
			lines.append(f'// … {hidden} line{"" if hidden == 1 else "s"} hidden')
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

def code_part(line: str) -> str:
	''' A line of C without its `//` comment and the spaces at its end. '''
	for match in TOKEN.finditer(line):
		if match.group(0).startswith('//'):
			return line[:match.start()].rstrip()
	return line.rstrip()

# The first line of an `if`, an `else if` or an `else`.
BRANCH = re.compile(r'(?:else\s+)?if\s*\(|else$')

def hide_lines(lines: List[str], patterns: List['re.Pattern'], names: Set[str]) -> Tuple[List[str], int]:
	''' Take statements out of pseudocode, and what they would leave empty: the work behind `hide` and `ignore` of `CFunc.text`.

	A line that one of `patterns` matches is a statement to take out, and so is a statement that is nothing but a call of one of `names`. Returns the lines that stay, and how many went.
	'''
	count = len(lines)
	code = [code_part(line) for line in lines]
	indent = [len(line) - len(line.lstrip(' ')) for line in lines]
	hidden = [False] * count
	call = re.compile(r'\s*(?:' + '|'.join(re.escape(name) for name in sorted(names)) + r')\(') if names else None

	def is_open(n: int) -> bool:
		# The header of an `if` without braces ends neither a statement nor a block, and neither does a wrapped line.
		text = code[n].strip()
		return bool(text) and not text.endswith((';', '{', '}', ':'))

	def is_else(n: int) -> bool:
		return n < count and not hidden[n] and re.match(r'else\b', code[n].strip()) is not None

	def statement_end(n: int) -> Optional[int]:
		for last in range(n, min(n + 40, count)):
			if last > n and indent[last] <= indent[n]:
				return None
			if code[last].endswith(';'):
				return last
		return None

	def try_hide(first: int, last: int) -> bool:
		# Hides the statement in these lines, with every `if` or `else` it was the whole body of. Hides nothing where the rest would read differently.
		while first > 0 and is_open(first - 1):
			head = first - 1
			while head >= 0 and indent[head] >= indent[first]:
				head -= 1
			if head < 0:
				return False
			text = code[head].strip()
			if not BRANCH.match(text) or (text != 'else' and is_else(last + 1)):
				return False
			first = head
		for n in range(first, last + 1):
			hidden[n] = True
		return True

	n = 0
	while n < count:
		last = None
		if any(pattern.search(lines[n]) for pattern in patterns):
			last = n
		elif call and call.match(lines[n]):
			last = statement_end(n)
		if last is not None and try_hide(n, last):
			n = last
		n += 1

	# A block that lost every line goes with its `if` or `else`, which can empty the block around it in turn.
	emptied = True
	while emptied:
		emptied = False
		shown = [n for n in range(count) if not hidden[n]]
		for opening, closing in zip(shown, shown[1:]):
			if code[opening].strip() != '{' or code[closing].strip() != '}' or closing == opening + 1 or indent[opening] != indent[closing]:
				continue
			if opening == 0 or hidden[opening - 1]:
				continue
			head = opening - 1
			while head >= 0 and indent[head] > indent[opening]:
				head -= 1
			if head < 0 or indent[head] != indent[opening]:
				continue
			text = code[head].strip()
			if not BRANCH.match(text) or (text != 'else' and is_else(closing + 1)):
				continue
			if try_hide(head, closing):
				emptied = True
				break
	return [line for n, line in enumerate(lines) if not hidden[n]], sum(hidden)

class Call:
	''' Represent one call that a function makes. '''

	def __init__(self, site: int, kind: str, target: Optional['Func'], text: str, args: Optional[List[str]] = None):
		''' Init with the calling instruction's address, the kind of call, the called function, its text, and the arguments when the call was taken from pseudocode. '''
		self.site: int = site
		''' Address of the calling instruction. '''
		self.kind: str = kind
		''' `'direct'`: a call instruction with a code reference. `'tail'`: a jump to the start of another function. `'indirect'`: a call instruction without a code reference, through a register or memory. '''
		self.target: Optional[Func] = target
		''' The called function. `None` for an indirect call, or a target that is in no function. '''
		self.text: str = text
		''' The target's name (its address when it has none), or what an indirect call goes through: the operand such as `'X8'`, or the expression in a call from `CFunc.calls`. '''
		self.args: Optional[List[str]] = args
		''' The arguments as the pseudocode has them, in a call from `CFunc.calls`. `None` in a call from `Func.calls`, which reads the instructions. '''

	def to_dict(self) -> Dict[str, Any]:
		''' The call as a JSON-friendly `dict`, addresses as hex strings. `args` is there when the call has them. '''
		data = { 'site' : hex(self.site), 'kind' : self.kind, 'target' : hex(self.target.start) if self.target is not None else None, 'text' : self.text }
		if self.args is not None:
			data['args'] = list(self.args)
		return data

	def __repr__(self) -> str:
		args = f', args={self.args}' if self.args is not None else ''
		return f'<Call site={hex(self.site)}, kind={self.kind}, target={hex(self.target.start) if self.target is not None else None}, text={self.text}{args}>'

	def __hash__(self) -> int:
		return hash((self.site, self.kind, self.text))

	def __eq__(self, o: object) -> bool:
		return type(o) is Call and (self.site, self.kind, self.target, self.text, self.args) == (o.site, o.kind, o.target, o.text, o.args)

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

class IgnoreSet(collections.abc.MutableSet):
	''' The set behind `Func.ignore`: regular expressions that the open database keeps, so they are there again the next time it is opened. '''

	NODE = '$ ida_scripts ignore'
	TAG = 'B'

	def _load(self) -> Set[str]:
		# Outside IDA there is no database, and so nothing in the set: the documentation tools print it there.
		if not IN_IDA or not ida_netnode.netnode.exist(self.NODE):
			return set()
		data = ida_netnode.netnode(self.NODE, 0, False).getblob(0, self.TAG)
		try:
			return set(json.loads(data.decode('utf-8'))) if data else set()
		except ValueError:
			return set()

	def _store(self, patterns: Set[str]):
		if not IN_IDA:
			raise IDAError('Func.ignore is kept in a database, and there is none outside IDA')
		node = ida_netnode.netnode(self.NODE, 0, True)
		if patterns:
			node.setblob(json.dumps(sorted(patterns)).encode('utf-8'), 0, self.TAG)
		else:
			node.delblob(0, self.TAG)

	def __contains__(self, pattern: object) -> bool:
		return pattern in self._load()

	def __iter__(self) -> Iterator[str]:
		return iter(sorted(self._load()))

	def __len__(self) -> int:
		return len(self._load())

	def add(self, pattern: str):
		''' Add a regular expression. Raises `re.error` when it is not one. '''
		self.update([pattern])

	def discard(self, pattern: str):
		''' Remove a regular expression, when it is there. '''
		patterns = self._load()
		if pattern in patterns:
			self._store(patterns - { pattern })

	def update(self, *others: Iterable[str]):
		''' Add every regular expression of the given iterables. Raises `re.error`, and adds nothing, when one of them is none. '''
		added = { pattern for other in others for pattern in ([other] if isinstance(other, str) else other) }
		for pattern in added:
			re.compile(pattern)
		self._store(self._load() | added)

	def clear(self):
		''' Remove every regular expression. '''
		self._store(set())

	def __repr__(self) -> str:
		return repr(self._load())

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

	ignore: Set[str] = IgnoreSet()
	''' Regular expressions of callee names that `Func.callees`, `Func.calls`, `Func.outline` and `CFunc.calls` leave out, such as runtime helpers that drown the list. Searched for anywhere in the name (`re.search`). Empty by default, and kept in the database when it is changed in place, as by `Func.ignore.update([r'^rt_'])`.

	Changed in place (`add`, `update`, `discard`, `clear`), the set is there again after the database was saved and opened again. Assigning a plain `set` instead uses those patterns until the process ends, and stores nothing.
	'''

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
	def _lone_jump(self) -> Optional[int]:
		''' Where the function's only instruction jumps, when that is the start of another function. `None` for any other function. '''
		try:
			insn = Insn(self.start)
		except IDAError:
			return None
		if insn.size != self.size or insn.is_call:
			return None
		kinds = { x.type for x in idautils.XrefsFrom(self.start, 0) }
		target = insn.target
		if ida_xref.fl_F in kinds or target is None or target.addr == self.start:
			return None
		return target.addr if compat.func_start(target.addr) == target.addr else None

	@property
	def is_thunk(self) -> bool:
		''' Whether this function only jumps to another one: IDA marks it as a thunk, as it does an import stub, or it is a single jump to the start of another function. '''
		return bool(compat.func_flags(self.start) & ida_funcs.FUNC_THUNK) or self._lone_jump() is not None

	@property
	def thunk_target(self) -> Optional['Func']:
		''' The function a thunk jumps to. `None` when this is not a thunk, or when the target is in no function of the database, as for an import. '''
		target = compat.thunk_target(self.start)
		if target is None and not compat.func_flags(self.start) & ida_funcs.FUNC_THUNK:
			target = self._lone_jump()
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
			text = string_at(ref.addr)
			if text is not None:
				found.append((ref, text))
		return found

	def outline(self, width: int = 120, max_lines: int = 200) -> str:
		''' What the function does at a glance: the calls it makes, in order, and the texts it refers to.

		The first line has the function's address and name, and after `//` the first line of its comment. Then comes one line for each call: the address of the call, the name of the function called, and the first line of that function's comment. An indirect call shows as `(indirect)` with its operand, a tail call as `(tail)` with the name. Calls of the same function right after one another are one line that ends in their number, as in `x3`. Calls to a name that matches `Func.ignore` are left out. Under a line `data` come the strings the function refers to, and the addresses it refers to that have a comment.

		Parameters
		----------
		width : int, default = 120
			Cut every line to this many characters. `None` for whole lines.
		max_lines : int, default = 200
			Keep only the first `max_lines` lines, then a line `… N more lines`. `None` for all of them.

		Returns
		-------
		str
			The text, lines separated by `\\n`.
		'''
		def remark(text: str) -> str:
			return f'  // {first_line(text)}' if first_line(text) else ''
		rows = []
		for call in self.calls:
			if call.kind == 'indirect':
				label, about = f'(indirect) {call.text}', ''
			else:
				label = ('(tail) ' if call.kind == 'tail' else '') + call.text
				about = remark(call.target.comment) if call.target is not None else ''
			if rows and rows[-1][1] == label:
				rows[-1][2] += 1
			else:
				rows.append([call.site, label, 1, about])
		lines = [f'{hex(self.start)} {self.name}{remark(self.comment)}']
		lines += [f'  {hex(site)}  {label}{f" x{times}" if times > 1 else ""}{about}' for site, label, times, about in rows]
		data = []
		for ref in self.data_refs:
			text = string_at(ref.addr)
			if text is not None:
				data.append(f'  {hex(ref.addr)}  {ref.name}  {json.dumps(text, ensure_ascii=False)}')
			elif first_line(ref.comment):
				data.append(f'  {hex(ref.addr)}  {ref.name}{remark(ref.comment)}')
		if data:
			lines += ['data'] + data
		if max_lines is not None and len(lines) > max_lines:
			lines = lines[:max_lines] + [f'… {len(lines) - max_lines} more lines']
		return '\n'.join(cut(line, width) for line in lines)

	def __hash__(self) -> int:
		return self.start

	def __eq__(self, o: object) -> bool:
		return type(o) is Func and self.start == o.start

def string_at(ea: int) -> Optional[str]:
	''' The string literal that the database defines at an address, `None` when it defines none there. '''
	if not ida_bytes.is_strlit(ida_bytes.get_flags(ea)):
		return None
	data = ida_bytes.get_strlit_contents(ea, ida_bytes.get_item_size(ea), ida_nalt.get_str_type(ea)) or b''
	return data.decode('utf-8', 'replace')

def each_func(targets: Iterable[Any]) -> Iterator['Func']:
	''' A `Func` for each target. A list, tuple or other iterable among the targets stands for the functions in it. '''
	for target in targets:
		if isinstance(target, Func):
			yield target
		elif isinstance(target, (int, str, Pointer)) or not isinstance(target, collections.abc.Iterable):
			yield Func(target)
		else:
			yield from each_func(target)

def grep(pattern: str, funcs: Iterable[Union[int, str, Pointer, 'Func']], context: int = 0, limit: int = None) -> str:
	''' The pseudocode lines of several functions that match a regular expression: `CFunc.grep` over each of them.

	Parameters
	----------
	pattern : str
		Searched for anywhere in a line (`re.search`).
	funcs : iterable
		The functions to look in, each a `Func` or anything `Func` takes. `Func.search(r'^Player::')` gives such a list.
	context : int, default = 0
		How many lines to show before and after each match.
	limit : int, default = None
		Stop after this many functions had a match.

	Returns
	-------
	str
		For each function with a match: a line with its address and name, then its matching lines as `CFunc.grep` gives them. A blank line separates the functions. A function that cannot be decompiled is skipped, and a last line `// N not decompiled: …` names those. `''` when nothing matches.
	'''
	re.compile(pattern)
	parts, failed = [], []
	for f in each_func(funcs):
		if limit is not None and len(parts) >= limit:
			break
		try:
			found = f.decompile().grep(pattern, context)
		except DecompileError:
			failed.append(f.name or hex(f.start))
			continue
		if found:
			parts.append(f'{hex(f.start)} {f.name}\n{found}')
	if failed:
		parts.append(f'// {len(failed)} not decompiled: {", ".join(failed[:10])}{" …" if len(failed) > 10 else ""}')
	return '\n\n'.join(parts)

def show_code(*targets: Union[int, str, Pointer, 'Func'], max_lines: int = 120, **options):
	''' Print the pseudocode of one or more functions, each under a line with its address and name.

	The name in that line is IDA's, which the pseudocode may spell differently. A function that cannot be decompiled prints the reason in its place, and the others still print.

	Parameters
	----------
	*targets
		Each a `Func`, anything `Func` takes, or a list of those.
	max_lines : int, default = 120
		Print only the first `max_lines` lines of each function, as `CFunc.text` cuts them. `None` prints all of it.
	**options
		The other options of `CFunc.text`: `decls`, `shorten`, `start`, `hide` and `ignore`.
	'''
	parts = []
	for f in each_func(targets):
		try:
			body = f.pseudocode(max_lines=max_lines, **options)
		except DecompileError as error:
			body = f'// {error}'
		parts.append(f'// {hex(f.start)} {f.name}\n{body}')
	print('\n\n'.join(parts))

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
