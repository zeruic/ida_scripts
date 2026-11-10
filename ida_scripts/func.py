''' Provides class(es) for interacting with functions.

The module itself can be called as a shorthand, like `ptr`: `func('main')` is `Func('main')`.
'''

import sys
import types
from typing import *

from . import compat
from .compat import IN_IDA
from .utils import *
from .memory import Pointer, set_name
from .struc import *

if IN_IDA:
	import ida_name
	import ida_nalt
	import ida_typeinf
	import ida_hexrays
	import ida_lines
	import ida_pro

__all__ = ['Func', 'CFunc', 'CItem']

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
	def accessed_struct(self) -> StrucT:
		''' Find and return the `StrucT` accessed by this memptr/memref operation. '''
		assert self.op_id in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref], 'Op is not memptr or memref.'
		if self.op_id == ida_hexrays.cot_memptr:
			struct_tinfo = self.item.cexpr.x.type.get_pointed_object()
		elif self.op_id == ida_hexrays.cot_memref:
			struct_tinfo = self.item.cexpr.x.type
		return StrucT.find(str(struct_tinfo))

	@property
	def accessed_struct_member(self) -> MemberT:
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
		return self.parent_where(lambda parent: parent.op == ida_hexrays.cit_expr)

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
			self.graph = gb.graph
		return self.graph

	@property
	def body_root(self) -> CItem:
		''' The root node of the graph for this function. '''
		return next(networkx().topological_sort(self.body))

	@property
	def pseudocode(self) -> str:
		''' Pseudocode of the decompiled function. '''
		lines = self.decompiled.get_pseudocode()
		return '\n'.join([ida_lines.tag_remove(l.line) for l in lines])

	psuedocode = pseudocode
	''' The old, misspelt name of `CFunc.pseudocode`. '''


@auto_repr(['name', 'start', 'end', 'size'], { 'start' : hex, 'end' : hex, 'size' : hex})
class Func:
	''' Represent a function. '''

	@staticmethod
	def find(name: str) -> Optional['Func']:
		''' Find function by name. '''
		ea = ida_name.get_name_ea(compat.BADADDR, name)
		return Func(ea) if ea != compat.BADADDR and compat.func_start(ea) == ea else None

	@staticmethod
	def at(addr: Union[int, str, Pointer]) -> Optional['Func']:
		''' The function containing an address, `None` when it is in no function. '''
		start = compat.func_start(to_ea(addr))
		return Func(start) if start is not None else None

	func_at = at
	''' The old name of `Func.at`. '''

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
		return { arg.name:arg.type for arg in func_data }

	@property
	def comment(self) -> str:
		''' The function comment, repeated wherever the function is referenced. `''` when there is none. Assign to set it. '''
		return compat.func_comment(self.start)

	@comment.setter
	def comment(self, text: str):
		if not compat.set_func_comment(self.start, text):
			raise IDAError(f'cannot comment {self.name or hex(self.start)}')

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
		declaration = declaration.strip()
		if not declaration.endswith(';'):
			declaration += ';'
		done = bool(ida_typeinf.apply_cdecl(None, self.start, declaration, ida_typeinf.TINFO_DEFINITE))
		if done:
			compat.refresh_decompiler()
		return done

	def decompile(self) -> CFunc:
		''' Decompile this function. Raises `DecompileError` when the decompiler fails. '''
		cfunc, reason = compat.decompile(self.start)
		if not cfunc:
			raise DecompileError(f'cannot decompile {self.name or hex(self.start)}: {reason}')
		return CFunc(self, cfunc)

	def __hash__(self) -> int:
		return self.start

	def __eq__(self, o: object) -> bool:
		return type(o) is Func and self.start == o.start

class CallableModule(types.ModuleType):
	''' Lets this module be called, so `func` names both the module and the shorthand without one hiding the other. '''

	def __call__(self, target: Union[int, str, Pointer, Func]) -> Func:
		''' Initialise a `Func`. '''
		return Func(target)

sys.modules[__name__].__class__ = CallableModule
