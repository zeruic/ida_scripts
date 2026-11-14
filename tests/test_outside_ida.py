''' The package imports without IDA (the runner sets IDA_SCRIPTS_NO_IDA=1), and everything public is documented. '''

import inspect
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ida_scripts
from ida_scripts import compat

MODULES = ['memory', 'module', 'struc', 'func', 'misc', 'debugger', 'session']

def undocumented(module) -> list:
	missing = []
	if not (module.__doc__ or '').strip():
		missing.append(module.__name__)
	for name in module.__all__:
		item = getattr(module, name)
		if not (inspect.isclass(item) or inspect.isfunction(item)):
			continue
		if not (item.__doc__ or '').strip():
			missing.append(name)
		if inspect.isclass(item):
			for member, value in vars(item).items():
				if member.startswith('_'):
					continue
				value = getattr(value, '__func__', value)
				if (inspect.isfunction(value) or isinstance(value, property)) and not (value.__doc__ or '').strip():
					missing.append(f'{name}.{member}')
	return missing

class TestOutsideIda(unittest.TestCase):

	def test_no_ida(self):
		self.assertFalse(compat.IN_IDA)
		self.assertFalse(any(name.startswith('ida_') and name != 'ida_scripts' and not name.startswith('ida_scripts.') for name in sys.modules))

	def test_exports(self):
		for name in ('Pointer', 'ptr', 'Func', 'func', 'Database', 'IDAError', 'Xref', 'Insn', 'disasm'):
			self.assertIn(name, ida_scripts.__all__)
			self.assertTrue(hasattr(ida_scripts, name))
		self.assertTrue(callable(ida_scripts.func))
		self.assertTrue(inspect.ismodule(ida_scripts.func))

	def test_the_ignore_list_without_a_database(self):
		from ida_scripts.func import Func
		from ida_scripts.utils import IDAError
		self.assertEqual(Func.ignore, set())
		self.assertEqual(repr(Func.ignore), 'set()')
		with self.assertRaises(IDAError):
			Func.ignore.add('x')

	def test_pydoc_renders(self):
		import pydoc
		for name in MODULES:
			with self.subTest(name):
				text = pydoc.render_doc(sys.modules[f'ida_scripts.{name}'])
				self.assertIn(f'ida_scripts.{name}', text)

	def test_everything_public_has_a_docstring(self):
		for name in MODULES:
			with self.subTest(name):
				module = sys.modules[f'ida_scripts.{name}']
				self.assertEqual(undocumented(module), [])

if __name__ == '__main__':
	unittest.main(verbosity=1)
