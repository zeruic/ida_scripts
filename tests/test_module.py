''' `ida_scripts.module` against the fake debugger in `tests/fakes`. '''

import json

import harness
from harness import sym
from ida_scripts import compat, debugger
from ida_scripts.utils import IDAError
from ida_scripts.memory import Pointer, ptr
from ida_scripts.module import Module, file_name, same_module
import fakes
from fakes import process

D = fakes.ida_dbg
ENGINE = 'C:\\Game\\bin\\Engine.dll'
ENGINE_BASE = 0x7ff600000000
LIB = '/usr/lib/libfoo.dylib'
LIB_BASE = 0x200000000

class ModuleTestCase(harness.IDATestCase):

	def setUp(self):
		self.ida = process.install(self, process.FakeIDA.for_database())
		self.addCleanup(self.stop)

	def stop(self):
		if self.ida.state != D.DSTATE_NOTASK:
			debugger.dbg.stop()

	def run_process(self):
		''' Start, load two libraries, and stop at `compute`. '''
		self.ida.program = [('load', LIB, LIB_BASE, 0x2000), ('load', ENGINE, ENGINE_BASE, 0x10000), ('exec', 1, sym('compute'))]
		debugger.dbg.start(self.ida.input_path)
		debugger.Breakpoint.add('_compute')
		debugger.dbg.resume()

	@property
	def main(self) -> Module:
		return Module.find(self.ida.input_path)

class TestNames(harness.IDATestCase):

	def test_file_name(self):
		self.assertEqual(file_name('/usr/lib/libfoo.dylib'), 'libfoo.dylib')
		self.assertEqual(file_name('C:\\Game\\Engine.dll'), 'Engine.dll')
		self.assertEqual(file_name('Engine.dll'), 'Engine.dll')

	def test_same_module(self):
		self.assertTrue(same_module(ENGINE, 'engine.DLL'))
		self.assertTrue(same_module(ENGINE, 'c:/game/bin/engine.dll'))
		self.assertTrue(same_module(LIB, LIB))
		self.assertFalse(same_module(LIB, 'libfoo'))
		self.assertFalse(same_module(LIB, ''))
		self.assertFalse(same_module('', 'x'))

class TestWithoutProcess(ModuleTestCase):

	def test_nothing_is_loaded(self):
		self.assertEqual(Module.all_modules(), [])
		self.assertIsNone(Module.find('sample'))
		self.assertIsNone(Module.containing(sym('compute')))
		self.assertIsNone(ptr('_compute').module)

class TestModules(ModuleTestCase):

	def test_all_modules(self):
		self.run_process()
		modules = Module.all_modules()
		self.assertEqual([(m.name, m.addr, m.size) for m in modules], [(self.ida.input_path, self.ida.image_base, self.ida.image_size), (LIB, LIB_BASE, 0x2000), (ENGINE, ENGINE_BASE, 0x10000)])
		self.assertEqual(modules, debugger.dbg.modules)

	def test_find(self):
		self.run_process()
		engine = Module(ENGINE, ENGINE_BASE, 0x10000)
		for name in ('Engine.dll', 'engine.dll', 'ENGINE.DLL', ENGINE, 'c:\\game\\bin\\engine.dll', 'C:/Game/bin/Engine.dll'):
			with self.subTest(name):
				self.assertEqual(Module.find(name), engine)
		self.assertEqual(Module.find('libfoo.dylib').addr, LIB_BASE)
		self.assertEqual(Module.find('sample').name, self.ida.input_path)
		self.assertIsNone(Module.find('Engine'))
		self.assertIsNone(Module.find('other.dll'))

	def test_containing(self):
		self.run_process()
		self.assertEqual(Module.containing(ENGINE_BASE).addr, ENGINE_BASE)
		self.assertEqual(Module.containing(ENGINE_BASE + 0xffff).addr, ENGINE_BASE)
		self.assertIsNone(Module.containing(ENGINE_BASE + 0x10000))
		self.assertEqual(Module.containing('_compute'), self.main)
		self.assertEqual(Module.containing(Pointer(LIB_BASE + 4)).name, LIB)
		self.assertIsNone(Module.containing(0x10))
		self.assertEqual(ptr('_compute').module, self.main)
		self.assertTrue(self.main.contains('_compute'))
		self.assertFalse(Module('x', 0x1000, 0).contains(0x1000))

	def test_offsets(self):
		self.run_process()
		engine = Module.find('Engine.dll')
		self.assertEqual(engine + 0x4de0, ENGINE_BASE + 0x4de0)
		self.assertIsInstance(engine + 0x4de0, Pointer)
		self.assertEqual(Pointer(engine), ENGINE_BASE)

	def test_the_input_file_maps_to_the_database(self):
		self.ida.main_base = self.ida.image_base + 0x4000
		self.run_process()
		main = Module.containing(self.ida.main_base)
		self.assertTrue(main.is_input_file)
		self.assertFalse(Module.find('Engine.dll').is_input_file)
		self.assertEqual(main.static_base, compat.image_base())
		self.assertEqual(main.to_static(self.ida.main_base + 0x10), compat.image_base() + 0x10)
		self.assertEqual(main.from_static(compat.image_base() + 0x10), self.ida.main_base + 0x10)
		self.assertIsInstance(main.from_static('_compute'), Pointer)
		self.assertEqual(main.to_static(main.from_static('_compute')), sym('compute'))

	def test_other_modules_need_a_static_base(self):
		self.run_process()
		engine = Module.find('Engine.dll')
		self.assertIsNone(engine.static_base)
		with self.assertRaisesRegex(IDAError, 'the database address of Engine.dll is unknown, set its static_base first'):
			engine.to_static(ENGINE_BASE + 0x4de0)
		with self.assertRaises(IDAError):
			engine.from_static(0x10004de0)
		engine.static_base = 0x10000000
		self.assertEqual(engine.to_static(ENGINE_BASE + 0x4de0), 0x10004de0)
		self.assertEqual(engine.from_static(0x10004de0), ENGINE_BASE + 0x4de0)
		self.assertEqual(Module.find('engine.dll').static_base, 0x10000000)
		Module.find('Engine.dll').static_base = '0x20000000'
		self.assertEqual(engine.static_base, 0x20000000)
		engine.static_base = None
		self.assertIsNone(Module.find('Engine.dll').static_base)

	def test_addresses_outside_the_module(self):
		self.run_process()
		engine = Module.find('Engine.dll')
		engine.static_base = 0x10000000
		with self.assertRaisesRegex(IDAError, r'0x7ff600010000 is not inside Engine.dll \(0x7ff600000000-0x7ff600010000\)'):
			engine.to_static(ENGINE_BASE + 0x10000)
		with self.assertRaisesRegex(IDAError, 'is not inside Engine.dll in the database'):
			engine.from_static(0x0fffffff)

	def test_json_and_equality(self):
		self.run_process()
		engine = Module.find('Engine.dll')
		self.assertEqual(json.loads(json.dumps(engine.to_dict())), { 'name' : ENGINE, 'addr' : hex(ENGINE_BASE), 'size' : 0x10000 })
		self.assertIn('Engine.dll', repr(engine))
		self.assertEqual(engine, Module(ENGINE, ENGINE_BASE, 1))
		self.assertNotEqual(engine, Module(ENGINE, ENGINE_BASE + 1, 0x10000))
		self.assertEqual(len({ engine, Module.find('engine.dll') }), 1)

	def test_the_recorded_list_stands_in_when_ida_lists_nothing(self):
		self.run_process()
		self.ida.lists_modules = False
		self.assertEqual([m.name for m in Module.all_modules()], [self.ida.input_path, LIB, ENGINE])
		self.assertEqual(Module.find('engine.dll').addr, ENGINE_BASE)

	def test_modules_go_with_the_process(self):
		self.run_process()
		debugger.dbg.stop()
		self.assertEqual(Module.all_modules(), [])
		self.assertIsNone(ptr('_compute').module)

if __name__ == '__main__':
	harness.main()
