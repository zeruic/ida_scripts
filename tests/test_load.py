''' `load.py` reloads the package in place, the way it is used from IDA's File > Script file. '''

import os

import harness
from harness import sym

LOAD = os.path.join(os.path.dirname(harness.TESTS), 'load.py')

class TestLoad(harness.IDATestCase):

	def run_load(self) -> dict:
		scope = { '__name__' : '__main__', '__file__' : LOAD }
		with open(LOAD) as file:
			exec(compile(file.read(), LOAD, 'exec'), scope)
		return scope

	def test_names_without_prefix(self):
		scope = self.run_load()
		self.assertEqual(scope['ptr']('_hero').addr, sym('hero'))
		self.assertEqual(scope['func']('_compute').name, '_compute')
		self.assertEqual(scope['Func'].find('_add').start, sym('add'))
		for name in ('Pointer', 'Database', 'IDAError', 'disasm', 'Xref', 'Insn'):
			self.assertIn(name, scope)

	def test_reload_picks_up_fresh_modules(self):
		first = self.run_load()
		second = self.run_load()
		self.assertIsNot(first['Pointer'], second['Pointer'])
		self.assertEqual(second['ptr']('_counter').u32(), 7)
		self.assertIsInstance(second['ptr']('_add').func, second['Func'])

	def test_unload_hook_runs_before_reload(self):
		import sys
		calls = []
		self.run_load()
		sys.modules['ida_scripts.debugger']._unload = lambda: calls.append('unloaded')
		self.run_load()
		self.assertEqual(calls, ['unloaded'])

if __name__ == '__main__':
	harness.main()
