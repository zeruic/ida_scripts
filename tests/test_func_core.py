import json
from unittest import mock

import harness
from harness import sym
from ida_scripts import compat
from ida_scripts.utils import IDAError, DecompileError
from ida_scripts.memory import Pointer
from ida_scripts import func
from ida_scripts.func import Func, CFunc

class TestFunc(harness.IDATestCase):

	def test_find(self):
		self.assertEqual(Func.find('_compute').start, sym('compute'))
		self.assertIsNone(Func.find('_hero'))
		self.assertIsNone(Func.find('no_such_function'))
		# A C name finds the symbol that Mach-O gives a leading underscore.
		self.assertEqual(Func.find('compute'), Func.find('_compute'))
		self.assertIsNone(Func.find('hero'))
		self.assertIsNone(Func.find('__compute'))

	def test_at(self):
		inside = sym('compute') + 12
		self.assertEqual(Func.at(inside).start, sym('compute'))
		self.assertEqual(Func.at(Pointer(inside)), Func.at('_compute'))
		self.assertIsNone(Func.at(sym('hero')))
		self.assertIsNone(Func.at(0x10))

	def test_construct(self):
		start = sym('compute')
		for target in (start, start + 8, '_compute', 'compute', Pointer(start), Func(start)):
			self.assertEqual(Func(target).start, start)
			self.assertEqual(func(target), Func(start))
		for bad in (sym('hero'), '_hero', 0x10):
			with self.assertRaises(LookupError):
				Func(bad)
		with self.assertRaises(LookupError):
			func('no_such_function')

	def test_bounds(self):
		f = Func('_compute')
		self.assertEqual(f.end, sym('apply'))
		self.assertEqual(f.size, sym('apply') - sym('compute'))
		self.assertEqual(f.chunks, [(f.start, f.end)])
		self.assertTrue(f.contains(f.start))
		self.assertTrue(f.contains(Pointer(f.end - 4)))
		self.assertFalse(f.contains(f.end))
		self.assertFalse(f.contains('_hero'))

	def test_shorthand_is_the_module(self):
		import inspect
		import ida_scripts
		self.assertTrue(inspect.ismodule(ida_scripts.func))
		self.assertIs(ida_scripts.func.Func, Func)
		self.assertEqual(ida_scripts.func('_add'), Func('_add'))

	def test_identity(self):
		a, b = Func('_add'), Func(sym('add') + 4)
		self.assertEqual(a, b)
		self.assertEqual(len({ a, b, Func('_mul') }), 2)
		self.assertNotEqual(a, sym('add'))
		self.assertEqual(repr(a), f'<Func name=_add, start={hex(a.start)}, end={hex(a.end)}, size={hex(a.size)}>')
		self.assertEqual(json.loads(json.dumps(a.to_dict()))['start'], hex(a.start))

	def test_every_function(self):
		starts = list(compat.func_starts())
		self.assertEqual(len(starts), compat.func_count())
		self.assertEqual(starts, sorted(starts))
		self.assertIn(sym('main'), starts)

	def test_thunk_target(self):
		self.assertIsNone(compat.thunk_target(sym('compute')))
		self.assertIsNotNone(compat.thunk_target(sym('printf')))

	def test_type(self):
		arguments = Func('_main').arguments
		self.assertEqual(list(arguments)[:2], ['argc', 'argv'])
		self.assertTrue(Func('_main').tif.is_func())
		# Observed: the types were empty, because they belonged to function details that were gone by then.
		self.assertEqual((str(arguments['argc']), arguments['argc'].get_size()), ('int', 4))
		self.assertTrue(arguments['argv'].is_ptr())

class TestDecompile(harness.IDATestCase):

	fresh = True

	def test_pseudocode(self):
		cfunc = Func('_compute').decompile()
		self.assertIsInstance(cfunc, CFunc)
		self.assertEqual(cfunc.original, Func('_compute'))
		self.assertIn('add(', cfunc.pseudocode)
		self.assertIn('mul(', cfunc.pseudocode)
		self.assertNotIn('\x01', cfunc.pseudocode)

	def test_failure(self):
		with mock.patch.object(compat, 'decompile', lambda start: (None, 'broken')):
			with self.assertRaisesRegex(DecompileError, '_compute.*broken'):
				Func('_compute').decompile()
		self.assertEqual(compat.decompile(sym('hero'))[0], None)
		self.assertTrue(compat.decompile(sym('hero'))[1])

	def test_tree_needs_networkx(self):
		import sys
		# None in sys.modules makes the import fail, as it does where networkx is not installed.
		with mock.patch.dict(sys.modules, { 'networkx' : None }):
			with self.assertRaisesRegex(IDAError, 'networkx'):
				Func('_compute').decompile().body
		self.assertIn('add(', Func('_compute').decompile().pseudocode)

	def test_tree_with_networkx(self):
		try:
			import networkx
		except ImportError:
			self.skipTest('networkx is not installed')
		cfunc = Func('_compute').decompile()
		self.assertIsInstance(cfunc.body, networkx.DiGraph)
		self.assertGreater(len(cfunc.body), 0)
		self.assertEqual(cfunc.body_root.op, 'block')

	def test_comment(self):
		f = Func('_leaf')
		self.assertEqual(f.comment, '')
		f.comment = 'returns the counter'
		self.assertEqual(f.comment, 'returns the counter')
		self.assertEqual(compat.func_comment(f.start, True), 'returns the counter')
		self.assertIn('returns the counter', f.decompile().pseudocode)
		f.comment = 'changed'
		self.assertIn('changed', f.decompile().pseudocode)
		f.comment = ''
		self.assertEqual(f.comment, '')

	def test_prototype(self):
		f = Func('_add')
		f.prototype = 'int __fastcall add(int left, int right)'
		self.assertIn('int left', f.prototype)
		self.assertIn('int right', f.prototype)
		self.assertEqual(list(f.arguments), ['left', 'right'])
		self.assertIn('left + right', f.decompile().pseudocode)
		self.assertTrue(f.set_prototype('int __fastcall add(int a, int b);'))
		self.assertIn('a + b', f.decompile().pseudocode)
		self.assertFalse(f.set_prototype('this is not C'))
		with self.assertRaises(IDAError):
			f.prototype = 'no_such_type_t add(int)'
		self.assertIn('int a', f.prototype)

	def test_rename_reaches_the_pseudocode(self):
		caller = Func('_dispatch')
		self.assertIn('mul(', caller.decompile().pseudocode)
		target = Func('_mul')
		self.assertTrue(target.rename('times'))
		self.assertEqual(target.name, 'times')
		self.assertEqual(Func.find('times'), target)
		self.assertIn('times(', caller.decompile().pseudocode)
		target.name = 'product'
		self.assertIn('product(', caller.decompile().pseudocode)
		self.assertFalse(target.rename('_add'))
		with self.assertRaises(IDAError):
			target.name = '_add'
		self.assertTrue(target.rename('_add', force=True))
		self.assertTrue(target.name.startswith('_add_'))

if __name__ == '__main__':
	harness.main()
