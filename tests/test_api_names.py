''' Every IDAPython name the package refers to exists in the running IDA, and none is a deprecated one. '''

import importlib
import os
import re

import harness
from ida_scripts import compat
import ida_idaapi

PACKAGE = os.path.join(os.path.dirname(harness.TESTS), 'ida_scripts')
STUBS = os.path.dirname(ida_idaapi.__file__)
REFERENCE = re.compile(r'\b(ida_[a-z_0-9]+|idc|idautils|idaapi)\.([A-Za-z_][A-Za-z_0-9]*)')

# These still work in 9.4 but call deprecated functions themselves, so they warn.
WARNING = { 'idautils.Functions', 'idautils.FuncItems', 'idautils.Chunks' }

def deprecated(module: str) -> set:
	path = os.path.join(STUBS, module + '.py')
	if not os.path.exists(path):
		return set()
	with open(path) as file:
		return set(re.findall(r'^([\w.]+) = ida_idaapi\._ida_deprecated\(', file.read(), re.M))

def references():
	for name in sorted(os.listdir(PACKAGE)):
		if name.endswith('.py'):
			with open(os.path.join(PACKAGE, name)) as file:
				for number, line in enumerate(file, 1):
					for module, attribute in REFERENCE.findall(line):
						yield name, number, module, attribute

def problem(file: str, module: str, attribute: str) -> str:
	try:
		target = importlib.import_module(module)
	except ImportError:
		return f'module {module} does not exist in this IDA'
	if not hasattr(target, attribute):
		return 'does not exist in this IDA'
	# compat.py keeps the old spellings on purpose, as fallbacks for IDA before 9.4.
	if file != 'compat.py':
		if attribute in deprecated(module):
			return 'is deprecated'
		if f'{module}.{attribute}' in WARNING:
			return 'warns in 9.4, use the shim in compat'
	return ''

class TestApiNames(harness.IDATestCase):

	def test_names_exist_and_are_current(self):
		problems = {}
		found = 0
		for file, line, module, attribute in references():
			found += 1
			reason = problem(file, module, attribute)
			if reason:
				problems.setdefault(file, []).append(f'line {line}: {module}.{attribute} {reason}')
		self.assertGreater(found, 50)
		for file in sorted(os.listdir(PACKAGE)):
			with self.subTest(file):
				self.assertEqual(problems.get(file, []), [])

if __name__ == '__main__':
	harness.main()
