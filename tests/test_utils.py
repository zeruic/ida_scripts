import json

import harness
from harness import sym
from ida_scripts.utils import *
from ida_scripts.memory import Pointer
from ida_scripts.func import Func

@auto_repr(['name', 'address', 'child', 'missing'], { 'address' : hex, 'missing' : hex })
class Thing:
	def __init__(self, child = None):
		self.name = 'thing'
		self.address = 0x1000
		self.child = child
		self.missing = None

class TestToEa(harness.IDATestCase):

	def test_int_and_hex_string(self):
		self.assertEqual(to_ea(0x1234), 0x1234)
		self.assertEqual(to_ea('0x1234'), 0x1234)
		self.assertEqual(to_ea(' 0X10 '), 0x10)

	def test_name(self):
		self.assertEqual(to_ea('_hero'), sym('hero'))

	def test_name_without_its_underscore(self):
		self.assertEqual(name_ea('_hero'), sym('hero'))
		self.assertEqual(name_ea('hero'), sym('hero'))
		self.assertEqual(to_ea('hero'), sym('hero'))
		self.assertEqual(to_ea('compute'), sym('compute'))
		self.assertIsNone(name_ea('no_such_symbol'))
		self.assertIsNone(name_ea('__hero'))

	def test_unknown_name(self):
		with self.assertRaises(LookupError):
			to_ea('no_such_symbol')

	def test_objects(self):
		self.assertEqual(to_ea(Pointer(sym('hero'))), sym('hero'))
		self.assertEqual(to_ea(Func(sym('compute') + 8)), sym('compute'))

	def test_rejects_non_addresses(self):
		for bad in (True, 1.5, None, [1]):
			with self.assertRaises(TypeError):
				to_ea(bad)

class TestAutoRepr(harness.IDATestCase):

	def test_repr(self):
		self.assertEqual(repr(Thing()), '<Thing name=thing, address=0x1000, child=None, missing=None>')

	def test_to_dict_is_json(self):
		data = Thing(Thing()).to_dict()
		self.assertEqual(data['address'], '0x1000')
		self.assertEqual(data['child']['name'], 'thing')
		self.assertIsNone(data['missing'])
		json.dumps(data)

	def test_jsonable(self):
		value = jsonable({ 1 : [Pointer(0x10), b'\x01\xff', (1, 2.5, None)], 'f' : Func(sym('add')) })
		self.assertEqual(value['1'], ['0x10', '01ff', [1, 2.5, None]])
		self.assertEqual(value['f']['name'], '_add')
		json.dumps(value)

class TestText(harness.IDATestCase):

	def test_cut(self):
		self.assertEqual(cut('abcdef', 4), 'abc…')
		self.assertEqual(cut('abcd', 4), 'abcd')
		self.assertEqual(cut('abcdef', None), 'abcdef')
		self.assertEqual(cut('abcdef', 1), '…')
		self.assertEqual(cut('', 3), '')

	def test_first_line(self):
		self.assertEqual(first_line('  one \n two'), 'one')
		self.assertEqual(first_line('\n\nlater'), 'later')
		self.assertEqual(first_line(''), '')
		self.assertEqual(first_line(None), '')

class TestHexdump(harness.IDATestCase):

	def test_layout(self):
		text = hexdump(b'ABCDEFGHIJKLMNOPQ\x00', start_offset=0x100)
		lines = text.splitlines()
		self.assertEqual(len(lines), 2)
		self.assertTrue(lines[0].startswith('00000100:  41 42 43'))
		self.assertTrue(lines[0].endswith('|ABCDEFGHIJKLMNOP|'))
		self.assertTrue(lines[1].endswith('|Q.|'))

if __name__ == '__main__':
	harness.main()
