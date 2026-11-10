import hashlib
import json
import os
import py_compile
import re
import sys
import tempfile
from unittest import mock

import harness
from harness import sym
from ida_scripts import compat
from ida_scripts import memory
from ida_scripts.utils import IDAError, DecompileError
from ida_scripts.memory import Pointer, Insn
from ida_scripts import func
from ida_scripts.func import Func, CFunc, CItem, Call, export_fingerprints, match_functions, shorten_identifiers
import ida_funcs
import ida_ua

FAKES = os.path.join(harness.TESTS, 'fakes')

def load_networkx():
	''' The real `networkx` when it is installed, else the stand-in in tests/fakes, which is on `sys.path` only while it is imported. '''
	try:
		import networkx
		return networkx
	except ImportError:
		pass
	sys.path.insert(0, FAKES)
	try:
		import networkx
	finally:
		sys.path.remove(FAKES)
	return networkx

def names(funcs):
	return [f.name for f in funcs]

class TestLookup(harness.IDATestCase):

	def test_search(self):
		self.assertEqual(names(Func.search('^_(add|mul)$')), ['_add', '_mul'])
		found = Func.search('_')
		self.assertEqual([f.start for f in found], sorted(compat.func_starts()))
		self.assertEqual(names(Func.search('_', limit=2)), names(found[:2]))
		self.assertEqual(Func.search('_', limit=0), [])
		self.assertEqual(names(Func.search('shortening$')), ['_this_is_a_very_long_function_name_used_to_test_identifier_shortening'])
		self.assertEqual(Func.search('no_such_function'), [])
		self.assertEqual(Func.search('_hero'), [])
		with self.assertRaises(re.error):
			Func.search('(')

	def test_all(self):
		every = Func.all()
		self.assertFalse(isinstance(every, list))
		every = list(every)
		self.assertTrue(all(isinstance(f, Func) for f in every))
		self.assertEqual([f.start for f in every], list(compat.func_starts()))
		self.assertIn(Func('_main'), every)

	def test_thunks(self):
		stub = Func('_printf')
		self.assertTrue(stub.is_thunk)
		# The stub jumps to the import, which is in no function.
		self.assertIsNone(stub.thunk_target)
		self.assertFalse(Func('_compute').is_thunk)
		self.assertIsNone(Func('_compute').thunk_target)

class TestCalls(harness.IDATestCase):

	def test_direct(self):
		calls = Func('_compute').calls
		self.assertEqual([call.kind for call in calls], ['direct'] * 4)
		self.assertEqual([call.text for call in calls], ['_add', '_mul', '_leaf', '_add'])
		self.assertEqual([call.target for call in calls], [Func('_add'), Func('_mul'), Func('_leaf'), Func('_add')])
		sites = [insn.address for insn in Func('_compute').insns if insn.is_call]
		self.assertEqual([call.site for call in calls], sites)
		self.assertEqual(names(Func('_greet').callees), ['_printf'])

	def test_indirect(self):
		calls = Func('_apply').calls
		self.assertEqual(len(calls), 1)
		self.assertEqual((calls[0].kind, calls[0].target, calls[0].text), ('indirect', None, 'X8'))
		self.assertEqual(Insn(calls[0].site).mnem, 'BLR')
		self.assertEqual(Func('_apply').callees, [])

	def test_tail(self):
		calls = Func('_tail_caller').calls
		self.assertEqual(len(calls), 1)
		self.assertEqual((calls[0].kind, calls[0].target, calls[0].text), ('tail', Func('_add'), '_add'))
		self.assertEqual(Insn(calls[0].site).mnem, 'B')
		self.assertEqual(names(Func('_tail_caller').callees), ['_add'])

	def test_jumps_inside_are_not_calls(self):
		# dispatch is full of branches and a jump table, but only calls add and mul.
		calls = Func('_dispatch').calls
		self.assertEqual([(call.kind, call.text) for call in calls], [('direct', '_add'), ('direct', '_mul')])
		self.assertTrue(any(insn.target for insn in Func('_dispatch').insns if not insn.is_call))
		self.assertEqual(Func('_leaf').calls, [])

	def test_callees(self):
		self.assertEqual(names(Func('_compute').callees), ['_add', '_mul', '_leaf'])
		callees = Func('_main').callees
		self.assertEqual([f.start for f in callees], sorted(f.start for f in callees))
		self.assertEqual(len(callees), len(set(callees)))
		self.assertEqual(set(names(callees)), { '_compute', '_apply', '_tail_caller', '_dispatch', '_player_power', '_this_is_a_very_long_function_name_used_to_test_identifier_shortening', '_uses_strings', '_greet' })
		# main takes add's address for apply, which is not a call.
		self.assertNotIn('_add', names(callees))

	def test_callers(self):
		self.assertEqual(names(Func('_add').callers), ['_compute', '_tail_caller', '_dispatch'])
		self.assertEqual(names(Func('_printf').callers), ['_greet'])
		self.assertEqual(names(Func('_compute').callers), ['_main'])
		self.assertEqual(Func('_main').callers, [])

	def test_ignore(self):
		self.assertEqual(Func.ignore, set())
		with mock.patch.object(Func, 'ignore', { '^_mul$', 'lea' }):
			self.assertEqual([call.text for call in Func('_compute').calls], ['_add', '_add'])
			self.assertEqual(names(Func('_compute').callees), ['_add'])
			self.assertEqual(len(Func('_apply').calls), 1)
		with mock.patch.object(Func, 'ignore', { '_add' }):
			self.assertEqual(Func('_tail_caller').calls, [])
			# callers are not filtered
			self.assertEqual(names(Func('_add').callers), ['_compute', '_tail_caller', '_dispatch'])

	def test_xrefs_to(self):
		refs = Func('_add').xrefs_to
		self.assertEqual(refs, Pointer('_add').xrefs_to())
		self.assertEqual(sorted(ref.kind for ref in refs if ref.func), ['call', 'call', 'call', 'jump', 'offset'])
		self.assertTrue(all(ref.to == sym('add') for ref in refs))

	def test_call_json(self):
		calls = Func('_compute').calls + Func('_apply').calls + Func('_tail_caller').calls
		data = json.loads(json.dumps([call.to_dict() for call in calls]))
		self.assertEqual(data[0], { 'site' : hex(calls[0].site), 'kind' : 'direct', 'target' : hex(sym('add')), 'text' : '_add' })
		self.assertEqual(data[4], { 'site' : hex(calls[4].site), 'kind' : 'indirect', 'target' : None, 'text' : 'X8' })
		self.assertEqual(data[5]['kind'], 'tail')
		self.assertIn('kind=tail', repr(calls[5]))
		self.assertEqual(calls[0], Func('_compute').calls[0])
		self.assertNotEqual(calls[0], calls[3])
		self.assertEqual(len(set(calls)), len(calls))

class TestSecondBuild(harness.IDATestCase):

	fixture = 'func_build2'

	def test_loop_is_not_a_call(self):
		self.assertTrue(any(insn.mnem.startswith('B') for insn in Func('_spread').insns))
		self.assertEqual(Func('_spread').calls, [])

	def test_recursion_is_a_call(self):
		calls = Func('_recurse').calls
		self.assertEqual([(call.kind, call.target) for call in calls], [('direct', Func('_recurse'))])
		self.assertEqual(names(Func('_recurse').callers), ['_recurse', '_main'])

	def test_jump_to_another_function(self):
		f = Func('_jump_to_times')
		self.assertEqual([(call.kind, call.text) for call in f.calls], [('tail', '_times')])
		self.assertIn('_jump_to_times', names(Func('_times').callers))

class TestThunkTarget(harness.IDATestCase):

	fixture = 'func_build2'
	fresh = True

	def test_thunk_to_a_function(self):
		f = Func('_jump_to_times')
		self.assertFalse(f.is_thunk)
		self.assertIsNone(f.thunk_target)
		self.assertTrue(ida_funcs.set_func_flag(f.start, ida_funcs.FUNC_THUNK, True))
		self.assertTrue(f.is_thunk)
		self.assertEqual(f.thunk_target, Func('_times'))

class TestData(harness.IDATestCase):

	def test_data_refs(self):
		self.assertEqual(Func('_leaf').data_refs, [sym('counter')])
		self.assertEqual(Func('_uses_strings').data_refs, sorted([sym('message'), Pointer('aPointerTarget').addr]))
		refs = Func('_main').data_refs
		self.assertTrue(all(isinstance(ref, Pointer) for ref in refs))
		self.assertEqual(refs, sorted(set(refs)))
		for name in ('hero', 'table', 'small_value', 'big_value', 'wide_text', 'add'):
			self.assertIn(sym(name), refs)
		self.assertEqual(Func('_compute').data_refs, [])

	def test_strings(self):
		self.assertEqual(Func('_greet').strings, [(Pointer('aHelloFixtureS'), 'hello fixture %s\n')])
		self.assertEqual(Func('_uses_strings').strings, [(Pointer('aPointerTarget'), 'pointer target')])
		self.assertEqual(Func('_main').strings, [(Pointer('_wide_text'), 'wide fixture')])
		self.assertEqual(Func('_compute').strings, [])
		address, text = Func('_greet').strings[0]
		self.assertIsInstance(address, Pointer)
		self.assertEqual(address.string(), text)

class TestCode(harness.IDATestCase):

	def test_insns(self):
		f = Func('_compute')
		insns = f.insns
		self.assertEqual(len(insns), f.size // 4)
		self.assertEqual([insn.address for insn in insns], list(range(f.start, f.end, 4)))
		self.assertEqual(insns[0].mnem, 'SUB')
		self.assertTrue(all(isinstance(insn, Insn) for insn in insns))

	def test_fingerprint(self):
		f = Func('_compute')
		expected = hashlib.sha256(' '.join(insn.mnem for insn in f.insns).encode()).hexdigest()
		self.assertEqual(f.fingerprint, expected)
		self.assertRegex(f.fingerprint, '^[0-9a-f]{64}$')
		self.assertNotEqual(Func('_add').fingerprint, Func('_mul').fingerprint)
		# The two import stubs are the same code at different addresses.
		self.assertEqual(Func('_printf').fingerprint, Func('_strlen').fingerprint)

	def test_disasm(self):
		f = Func('_add')
		lines = f.disasm().split('\n')
		self.assertEqual(len(lines), len(f.insns))
		self.assertEqual(lines[0], f'{hex(f.start)}  {Insn(f.start).text}')
		self.assertTrue(lines[0].split()[1] == 'SUB')
		self.assertIs(func.disasm, memory.disasm)
		self.assertEqual(func.disasm(f.start, f.end), f.insns)

class TestTails(harness.IDATestCase):
	''' greet gets tail_caller's code as a second chunk, which ends in a jump to add. '''

	fresh = True

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.tail = (sym('tail_caller'), compat.func_end(sym('tail_caller')))
		assert ida_funcs.del_func(sym('tail_caller'))
		assert ida_funcs.append_func_tail_ea(sym('greet'), *cls.tail)

	def test_chunks(self):
		f = Func('_greet')
		self.assertEqual(f.chunks, [self.tail, (sym('greet'), f.end)])
		self.assertTrue(f.contains(self.tail[0]))
		self.assertEqual(Func(self.tail[0]), f)

	def test_calls_from_every_chunk(self):
		calls = Func('_greet').calls
		self.assertEqual([(call.kind, call.text) for call in calls], [('tail', '_add'), ('direct', '_printf')])
		self.assertTrue(self.tail[0] <= calls[0].site < self.tail[1])
		self.assertEqual(names(Func('_greet').callees), ['_add', '_printf'])
		self.assertEqual(names(Func('_add').callers), ['_compute', '_dispatch', '_greet'])

	def test_insns_and_fingerprint(self):
		f = Func('_greet')
		insns = f.insns
		self.assertEqual(insns, memory.disasm(*self.tail) + memory.disasm(f.start, f.end))
		self.assertEqual(insns[0].address, self.tail[0])
		self.assertEqual(insns[-1].mnem, 'RET')
		self.assertEqual(f.fingerprint, hashlib.sha256(' '.join(insn.mnem for insn in insns).encode()).hexdigest())
		chunks = f.disasm().split('\n\n')
		self.assertEqual(len(chunks), 2)
		self.assertTrue(chunks[0].startswith(hex(self.tail[0])))
		self.assertTrue(chunks[1].startswith(hex(f.start)))

class TestJumpIntoOwnTail(harness.IDATestCase):
	''' tail_caller gets add's code as a second chunk, so its jump to add stays inside the function. '''

	fresh = True

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.tail = (sym('add'), compat.func_end(sym('add')))
		assert ida_funcs.del_func(sym('add'))
		assert ida_funcs.append_func_tail_ea(sym('tail_caller'), *cls.tail)

	def test_not_a_call(self):
		f = Func('_tail_caller')
		self.assertEqual(f.chunks[0], self.tail)
		jump = [insn for insn in f.insns if insn.target == sym('add')]
		self.assertEqual(len(jump), 1)
		self.assertEqual(f.calls, [])
		self.assertEqual(f.callees, [])

	def test_call_into_a_tail(self):
		calls = Func('_compute').calls
		self.assertEqual([(call.kind, call.text) for call in calls], [('direct', '_add'), ('direct', '_mul'), ('direct', '_leaf'), ('direct', '_add')])
		self.assertEqual(calls[0].target, Func('_tail_caller'))

class TestPseudocode(harness.IDATestCase):

	def test_lines(self):
		cfunc = Func('_compute').decompile()
		self.assertEqual(cfunc.lines, cfunc.pseudocode.split('\n'))
		self.assertEqual(cfunc.lines[0], '__int64 __fastcall compute(unsigned int a1)')
		self.assertEqual(cfunc.lines[-1], '}')
		self.assertFalse(any('\x01' in line or '\x02' in line for line in cfunc.lines))
		self.assertEqual(cfunc.text(), cfunc.pseudocode)

	def test_without_declarations(self):
		cfunc = Func('_compute').decompile()
		lines = cfunc.lines
		self.assertEqual(lines[2:6], ['  __int64 v1; // x0', '  unsigned int v3; // [xsp+Ch] [xbp-14h]', '  unsigned int v4; // [xsp+18h] [xbp-8h]', ''])
		self.assertEqual(cfunc.text(decls=False).split('\n'), lines[:2] + lines[6:])
		main = Func('_main').decompile()
		text = main.text(decls=False).split('\n')
		self.assertEqual(text[:3], ['int __fastcall main(int argc, const char **argv, const char **envp)', '{', '  v4 = compute(a1: argc);'])
		self.assertEqual(len(text), len(main.lines) - 8)
		# Nothing to drop
		for name in ('_player_power', '_greet'):
			cfunc = Func(name).decompile()
			self.assertEqual(cfunc.text(decls=False), cfunc.pseudocode)

	def test_shorten(self):
		text = Func('_main').decompile().text(shorten=12)
		self.assertIn('v9 = v8 + this_is_a_ve…(a1: (unsigned int)argc);', text)
		self.assertNotIn('this_is_a_very', text)
		self.assertIn('uses_strings()', text)
		self.assertIn('v8 = v7 + player_power(a1: &hero);', text)
		greet = Func('_greet').decompile().text(shorten=3)
		self.assertIn('pri…(a1: "hello fixture %s\\n", a1)', greet)
		compute = Func('_compute').decompile().text(shorten=2)
		self.assertIn('  __… v1; // x0', compute)
		self.assertIn('// [xsp+Ch] [xbp-14h]', compute)

	def test_shorten_identifiers(self):
		self.assertEqual(shorten_identifiers('long_name = other("long literal", \'ab\') + 0x1234ABCD; // long comment', 4), 'long… = othe…("long literal", \'ab\') + 0x1234ABCD; // long comment')
		self.assertEqual(shorten_identifiers('a /* inside */ + abcdef', 3), 'a /* inside */ + abc…')
		self.assertEqual(shorten_identifiers('x = "say \\"hi_there\\"" + y_long;', 3), 'x = "say \\"hi_there\\"" + y_l…;')
		self.assertEqual(shorten_identifiers('abc', 3), 'abc')

	def test_max_lines(self):
		cfunc = Func('_compute').decompile()
		total = len(cfunc.lines)
		self.assertEqual(cfunc.text(max_lines=3).split('\n'), cfunc.lines[:3] + [f'// … {total - 3} more lines'])
		self.assertEqual(cfunc.text(max_lines=total), cfunc.pseudocode)
		self.assertEqual(cfunc.text(max_lines=0), f'// … {total} more lines')
		short = cfunc.text(decls=False, max_lines=2, shorten=5).split('\n')
		self.assertEqual(short, ['__int… __fas… compu…(unsig… int a1)', '{', f'// … {total - 4 - 2} more lines'])
		with self.assertRaises(ValueError):
			cfunc.text(max_lines=-1)
		with self.assertRaises(ValueError):
			cfunc.text(shorten=0)

	def test_func_pseudocode(self):
		f = Func('_compute')
		self.assertEqual(f.pseudocode(), f.decompile().pseudocode)
		self.assertEqual(f.pseudocode(decls=False, max_lines=4), f.decompile().text(decls=False, max_lines=4))
		with self.assertRaises(TypeError):
			f.pseudocode(colour=True)
		with mock.patch.object(compat, 'decompile', lambda start: (None, 'broken')):
			with self.assertRaisesRegex(DecompileError, 'broken'):
				f.pseudocode()

	def test_grep(self):
		cfunc = Func('_compute').decompile()
		leaf = cfunc.lines.index('  v1 = leaf();')
		self.assertEqual(cfunc.grep('leaf', context=0), f'{leaf + 1}:  v1 = leaf();')
		self.assertEqual(cfunc.grep(r'leaf\(', context=1).split('\n'), [f'{leaf}-{cfunc.lines[leaf - 1]}', f'{leaf + 1}:{cfunc.lines[leaf]}', f'{leaf + 2}-{cfunc.lines[leaf + 1]}'])
		self.assertEqual(cfunc.grep('no such text'), '')
		dispatch = Func('_dispatch').decompile()
		groups = dispatch.grep(r'\b(add|mul)\(', context=1).split('\n--\n')
		self.assertEqual(len(groups), 2)
		self.assertTrue(all(len(group.split('\n')) == 3 for group in groups))
		self.assertRegex(groups[0], r'^\d+-.*\n\d+:.*mul\(.*\n\d+-')
		self.assertRegex(groups[1], r'\n\d+:.*add\(')
		# The first lines have nothing before them.
		self.assertTrue(cfunc.grep('compute', context=2).startswith('1:__int64'))
		with self.assertRaises(re.error):
			cfunc.grep('(')

	def test_save(self):
		cfunc = Func('_greet').decompile()
		folder = tempfile.mkdtemp(prefix='ida_scripts_test_')
		path = cfunc.save(os.path.join(folder, 'greet.c'))
		self.assertEqual(path, os.path.join(folder, 'greet.c'))
		with open(path, encoding='utf-8') as file:
			self.assertEqual(file.read(), cfunc.pseudocode + '\n')
		previous = os.getcwd()
		os.chdir(folder)
		try:
			relative = cfunc.save('again.c')
		finally:
			os.chdir(previous)
		self.assertTrue(os.path.isabs(relative))
		self.assertTrue(os.path.samefile(relative, os.path.join(folder, 'again.c')))
		with self.assertRaises(OSError):
			cfunc.save(os.path.join(folder, 'missing', 'x.c'))

class TestPseudocodeWithComment(harness.IDATestCase):

	fresh = True

	def test_comment_lines_stay(self):
		f = Func('_compute')
		f.comment = 'first line\nsecond line'
		cfunc = f.decompile()
		self.assertEqual(cfunc.lines[:3], ['// first line', '// second line', '__int64 __fastcall compute(unsigned int a1)'])
		self.assertEqual(cfunc.text(decls=False).split('\n'), cfunc.lines[:4] + cfunc.lines[8:])
		self.assertNotIn('v1; // x0', cfunc.text(decls=False))

class TestCall(harness.IDATestCase):

	def test_call_through_the_debugger(self):
		from ida_scripts import debugger
		fake = mock.Mock()
		fake.call.return_value = 42
		with mock.patch.object(debugger, 'dbg', fake, create=True):
			main = Func('_main')
			self.assertEqual(main.call(1, 'x'), 42)
			fake.call.assert_called_once_with(main.start, main.prototype, 1, 'x')
			self.assertEqual(fake.call.call_args[0][1], 'int __fastcall main(int argc, const char **argv, const char **envp)')

	def test_needs_a_prototype(self):
		from ida_scripts import debugger
		fake = mock.Mock()
		with mock.patch.object(debugger, 'dbg', fake, create=True):
			self.assertEqual(Func('_leaf').prototype, '')
			with self.assertRaisesRegex(IDAError, '_leaf.*prototype'):
				Func('_leaf').call()
			fake.call.assert_not_called()

class TestFingerprints(harness.IDATestCase):

	def test_export(self):
		exported = export_fingerprints()
		self.assertEqual(json.loads(json.dumps(exported)), exported)
		self.assertEqual(sorted(exported.values()), sorted(name for name in names(Func.all()) if name not in ('_printf', '_strlen')))
		self.assertEqual(exported[Func('_compute').fingerprint], '_compute')
		self.assertNotIn(Func('_printf').fingerprint, exported)

	def test_match_here(self):
		matched = match_functions(export_fingerprints())
		self.assertEqual(matched, { f.start : f.name for f in Func.all() if f.name not in ('_printf', '_strlen') })
		self.assertEqual(match_functions({}), {})
		self.assertEqual(match_functions({ Func('_printf').fingerprint : 'stub' }), {})

class TestFingerprintNames(harness.IDATestCase):

	fresh = True

	def test_named_only(self):
		f = Func('_leaf')
		self.assertTrue(f.rename(''))
		self.assertTrue(f.name.startswith('sub_'))
		self.assertNotIn(f.fingerprint, export_fingerprints())
		self.assertEqual(export_fingerprints(named_only=False)[f.fingerprint], f.name)

class TestMatchAcrossBuilds(harness.IDATestCase):
	''' Fingerprints from sample, matched in func_build2, where the same code has other names and addresses. '''

	fixture = 'func_build2'
	fresh = True

	@classmethod
	def setUpClass(cls):
		harness.open_fixture('sample')
		cls.exported = json.loads(json.dumps(export_fingerprints()))
		cls.sample = { name : sym(name) for name in ('add', 'mul', 'leaf', 'compute') }
		super().setUpClass()

	def test_match(self):
		matched = match_functions(self.exported)
		self.assertEqual(matched, { sym('times') : '_mul', sym('read_counter') : '_leaf', sym('combine') : '_compute' })
		for here, there in (('times', 'mul'), ('read_counter', 'leaf'), ('combine', 'compute')):
			self.assertNotEqual(sym(here), self.sample[there])
		# plus is add's code, but so is plus_again.
		self.assertEqual(Func('_plus').fingerprint, Func('_plus_again').fingerprint)
		self.assertIn(Func('_plus').fingerprint, self.exported)
		from ida_scripts.misc import rename_all
		self.assertEqual(rename_all(matched), 3)
		self.assertEqual({ start : Func(start).name for start in matched }, matched)
		self.assertEqual(names(Func('_compute').callees), ['_plus', '_mul', '_leaf'])

class TestTree(harness.IDATestCase):

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.networkx = load_networkx()
		cls.fake = cls.networkx.__file__.startswith(FAKES)

	@classmethod
	def tearDownClass(cls):
		if cls.fake:
			del sys.modules['networkx']

	def setUp(self):
		self.cfunc = Func('_compute').decompile()
		self.root = self.cfunc.body_root

	def test_graph(self):
		body = self.cfunc.body
		self.assertIs(self.cfunc.body, body)
		self.assertEqual(len(body), 26)
		self.assertIsInstance(self.root, CItem)
		self.assertEqual(self.root.op, 'block')
		self.assertIsNone(self.root.parent)
		self.assertEqual([child.op for child in self.root.children], ['expr', 'expr', 'expr', 'return'])
		self.assertEqual(self.root.n_children, 4)
		self.assertIs(body.graph['cfunc'], self.cfunc.decompiled)

	def test_items(self):
		calls = self.root.children_where(lambda item: item.op == 'call')
		self.assertEqual(len(calls), 4)
		self.assertEqual([call.called_function for call in calls], [Func('_add'), Func('_mul'), Func('_leaf'), Func('_add')])
		self.assertEqual([call.address for call in calls], [insn.address for insn in Func('_compute').insns if insn.is_call])
		self.assertEqual([item.num_value for item in self.root.children_where(lambda item: item.op == 'num')], [1, 2])
		first = self.root.child_where(lambda item: item.op == 'call')
		self.assertEqual(first, calls[0])
		self.assertEqual(first.label, 'call//__int64')
		self.assertEqual(first.type_name, '__int64')
		self.assertEqual(first.parent.op, 'asg')
		self.assertEqual(first.parent_where(lambda item: item.op == 'expr').op, 'expr')
		self.assertEqual(first.parent_expression, first.parent.parent)
		self.assertEqual(first.children[0].label, 'obj//.-1 _add//__int64 (__fastcall *)(_QWORD, __int64)')
		self.assertIsNone(self.root.child_where(lambda item: item.op == 'memptr'))
		self.assertIsNone(self.root.type_name)
		self.assertIn('op=call', repr(first))
		with self.assertRaises(AssertionError):
			self.root.num_value

	def test_subtree_search(self):
		query = { 'op' : 'asg', 'children' : [{ 'op' : 'var' }, { 'op' : 'call', 'children' : [{ 'op' : 'obj' }, { 'op' : 'var' }, { 'op' : 'num' }] }] }
		matches = self.root.subtree_search_strict(query)
		self.assertEqual(len(matches), 2)
		self.assertEqual([[item.op for item in level] for level in matches[0]], [['asg'], ['var', 'call'], ['obj', 'var', 'num']])
		self.assertEqual([match[2][2].num_value for match in matches], [1, 2])
		# A level must be complete: leaf() has only one child.
		self.assertEqual(len(self.root.subtree_search_strict({ 'op' : 'asg', 'children' : [{ 'op' : 'var' }, { 'op' : 'call' }] })), 3)
		named = self.root.subtree_search_strict({ 'op' : 'call', 'condition' : lambda item: item.called_function.name == '_leaf' })
		self.assertEqual(len(named), 1)
		with self.assertRaises(AssertionError):
			self.root.subtree_search_strict({ 'children' : [] })

	def test_items_outlive_the_cache(self):
		calls = self.root.children_where(lambda item: item.op == 'call')
		del self.cfunc, self.root
		compat.refresh_decompiler()
		self.assertEqual([call.children[0].label.split()[1].split('//')[0] for call in calls], ['_add', '_mul', '_leaf', '_add'])

	def test_flowers_still_fits(self):
		path = os.path.join(os.path.dirname(harness.TESTS), 'applications', 'flowers', 'main.py')
		py_compile.compile(path, doraise=True, cfile=os.path.join(tempfile.mkdtemp(prefix='ida_scripts_test_'), 'main.pyc'))
		with open(path) as file:
			source = file.read()
		for attribute in re.findall(r'\.(\w+)', source):
			if attribute in ('find', 'decompile'):
				self.assertTrue(hasattr(Func, attribute))
			elif attribute in ('body_root',):
				self.assertTrue(hasattr(CFunc, attribute))
			elif attribute in ('subtree_search_strict', 'child_where', 'called_function', 'accessed_struct', 'accessed_struct_member', 'parent_where', 'parent', 'type_name', 'num_value', 'op'):
				self.assertTrue(hasattr(CItem, attribute), attribute)

class FakeStruct:
	''' Stands in for `StrucT`, whose port is not this module's. '''

	found = []

	def __init__(self, name):
		self.name = name
		self.offsets = []

	@staticmethod
	def find(name):
		struct = FakeStruct(name)
		FakeStruct.found.append(struct)
		return struct

	def member_at_offset(self, offset):
		self.offsets.append(offset)
		return (self.name, offset)

class TestStructAccess(harness.IDATestCase):

	fresh = True

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		load_networkx()
		import ida_typeinf
		with open(os.path.join(harness.TESTS, 'fixtures', 'sample.c')) as file:
			source = file.read()
		assert ida_typeinf.parse_decls(None, source[source.index('struct Vec2'):source.index('int counter')], None, ida_typeinf.HTI_DCL) == 0
		assert Func('_player_power').set_prototype('int player_power(struct Player *player)')

	def test_accessed_struct(self):
		from ida_scripts import struc
		root = Func('_player_power').decompile().body_root
		members = root.children_where(lambda item: item.op == 'memptr')
		self.assertEqual(len(members), 3)
		FakeStruct.found = []
		with mock.patch.object(struc, 'StrucT', FakeStruct):
			self.assertEqual(sorted(member.accessed_struct_member for member in members), [('Player', 4), ('Player', 32), ('Player', 48)])
			self.assertEqual({ struct.name for struct in FakeStruct.found }, { 'Player' })
		with self.assertRaises(AssertionError):
			root.accessed_struct

	def test_with_the_struct_module(self):
		members = Func('_player_power').decompile().body_root.children_where(lambda item: item.op == 'memptr')
		self.assertEqual({ member.accessed_struct.name for member in members }, { 'Player' })
		self.assertEqual(sorted(member.accessed_struct_member.name for member in members), ['inventory', 'level', 'score'])

if __name__ == '__main__':
	harness.main()
