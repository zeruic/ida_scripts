import json
from unittest import mock

import harness
from harness import sym
from ida_scripts import compat
from ida_scripts.utils import IDAError, DebuggerError
from ida_scripts.memory import Pointer, ptr, Xref, Insn, disasm
from ida_scripts.func import Func

class FakeProcess:
	''' A debugged process with one mapped region, standing in for the debugger calls in `compat`. '''

	def __init__(self, base: int, data: bytes):
		self.base = base
		self.data = bytearray(data)
		self.writable = True

	def read(self, ea, size):
		start = ea - self.base
		if start < 0 or start + size > len(self.data):
			return None
		return bytes(self.data[start:start+size])

	def write(self, ea, data):
		start = ea - self.base
		if not self.writable or start < 0 or start + len(data) > len(self.data):
			return False
		self.data[start:start+len(data)] = data
		return True

	def attach(self):
		return mock.patch.multiple(compat, debugger_active=lambda: True, dbg_read=self.read, dbg_write=self.write)

class TestPointerRead(harness.IDATestCase):

	def test_construct(self):
		hero = sym('hero')
		for value in (hero, '_hero', hex(hero), Pointer(hero)):
			self.assertEqual(Pointer(value).addr, hero)
		self.assertEqual(ptr('_hero'), hero)
		self.assertEqual(Pointer(Func(sym('compute') + 4)).addr, sym('compute'))
		with self.assertRaises(LookupError):
			Pointer('nope')

	def test_integers(self):
		self.assertEqual(ptr('_counter').u32(), 7)
		self.assertEqual(ptr('_counter').s32(), 7)
		self.assertEqual(ptr('_small_value').u16(), 0xBEEF)
		self.assertEqual(ptr('_small_value').s16(), 0xBEEF - 0x10000)
		self.assertEqual(ptr('_small_value').u8(), 0xEF)
		self.assertEqual(ptr('_small_value').s8(), 0xEF - 0x100)
		self.assertEqual(ptr('_big_value').s64(), -1234567890123)
		self.assertEqual(ptr('_big_value').u64(), 2**64 - 1234567890123)

	def test_floats(self):
		self.assertEqual(ptr('_single_value').f32(), 1.5)
		self.assertEqual(ptr('_double_value').f64(), 2.25)

	def test_array(self):
		self.assertEqual(ptr('_table').array('i', 4), [10, 20, 30, 40])
		self.assertEqual(ptr('_table').array('H', 2), [10, 0])
		self.assertEqual(ptr('_hero').add(0x18).array('f', 2), [1.0, 2.0])

	def test_pointer_and_strings(self):
		target = ptr('_message').ptr()
		self.assertIsInstance(target, Pointer)
		self.assertEqual(target.string(), 'pointer target')
		self.assertEqual(ptr('_narrow_text').string(), 'narrow fixture')
		self.assertEqual(ptr('_narrow_text').string(read_length=6), 'narrow')
		self.assertEqual(ptr('_narrow_text').string(encoding='cp932'), 'narrow fixture')
		self.assertEqual(ptr('_wide_text').wstring(), 'wide fixture')
		self.assertEqual(ptr('_wide_text').wstring(read_length=4), 'wide')

	def test_read(self):
		self.assertEqual(ptr('_counter').read(4), b'\x07\x00\x00\x00')
		self.assertEqual(ptr('_counter').read(2, offset=4), b'\xef\xbe')
		self.assertEqual(ptr('_counter').read(0), b'')

	def test_unreadable(self):
		with self.assertRaises(IDAError):
			Pointer(0x10).read(4)
		with self.assertRaises(IDAError):
			Pointer(0x10).u32()
		end = compat.segment_bounds(sym('hero'))[1]
		with self.assertRaises(IDAError):
			Pointer(end - 2).read(0x4000)

	def test_hexdump(self):
		text = ptr('_narrow_text').hexdump_str(15)
		self.assertTrue(text.startswith('%08X:' % sym('narrow_text')))
		self.assertIn('|narrow fixture.|', text)
		offset = ptr('_narrow_text').hexdump_str(4, offset=7)
		self.assertTrue(offset.startswith('%08X:' % (sym('narrow_text') + 7)))

	def test_write_needs_a_process(self):
		for call in (lambda: ptr('_counter').write(b'\x01'), lambda: ptr('_counter').u32(1), lambda: ptr('_counter').swap(b'\x01')):
			with self.assertRaises(DebuggerError):
				call()

class TestPointerDebug(harness.IDATestCase):

	def setUp(self):
		self.process = FakeProcess(0x7000, b'\x11\x22\x33\x44' + b'live\x00' + b'\x00' * 23 + b'end')
		patcher = self.process.attach()
		patcher.start()
		self.addCleanup(patcher.stop)

	def test_reads_come_from_the_process(self):
		self.assertEqual(Pointer(0x7000).u32(), 0x44332211)
		self.assertEqual(Pointer(0x7004).string(), 'live')
		with self.assertRaises(IDAError):
			ptr('_counter').u32()

	def test_string_at_the_end_of_memory(self):
		self.assertEqual(Pointer(0x7000 + 32).string(read_length=3), 'end')
		self.process.data += b'\x00'
		self.assertEqual(Pointer(0x7000 + 32).string(), 'end')
		self.process.data[-1:] = b'!'
		with self.assertRaises(IDAError):
			Pointer(0x7000 + 32).string()

	def test_write(self):
		p = Pointer(0x7000)
		self.assertTrue(p.u16(0xABCD))
		self.assertEqual(p.read(4), b'\xcd\xab\x33\x44')
		self.assertTrue(p.write(b'\x01\x02', offset=2, verify=True))
		self.assertEqual(p.u32(), 0x0201ABCD)
		self.assertTrue(p.f32(0.5))
		self.assertEqual(p.f32(), 0.5)
		self.assertTrue(p.string('hi'))
		self.assertEqual(p.read(2), b'hi')
		self.assertTrue(p.wstring('ok'))
		self.assertEqual(p.wstring(read_length=2), 'ok')
		self.assertTrue(p.ptr(Pointer(0x1234)))
		self.assertEqual(p.ptr(), 0x1234)

	def test_failed_write(self):
		self.process.writable = False
		self.assertFalse(Pointer(0x7000).u32(1))
		self.assertFalse(Pointer(0x9000).write(b'\x00'))
		with self.assertRaises(DebuggerError):
			Pointer(0x7000).swap(b'\x00')

	def test_verify_catches_a_write_that_did_not_stick(self):
		with mock.patch.object(compat, 'dbg_write', lambda ea, data: True):
			self.assertTrue(Pointer(0x7000).write(b'\x11\x22', verify=True))
			self.assertFalse(Pointer(0x7000).write(b'\xff\xff', verify=True))

	def test_swap(self):
		self.assertEqual(Pointer(0x7000).swap(b'\xaa\xbb'), b'\x11\x22')
		self.assertEqual(Pointer(0x7000).read(2), b'\xaa\xbb')

class TestPointerDatabase(harness.IDATestCase):

	fresh = True

	def test_name(self):
		p = ptr('_sidekick')
		self.assertEqual(p.name, '_sidekick')
		self.assertEqual((p + 1).name, '')
		self.assertTrue(p.rename('buddy'))
		self.assertEqual(p.name, 'buddy')
		self.assertEqual(ptr('buddy'), p)
		p.name = 'pal'
		self.assertEqual(p.name, 'pal')
		self.assertFalse(p.rename('_hero'))
		with self.assertRaises(IDAError):
			p.name = '_hero'
		self.assertEqual(p.name, 'pal')
		self.assertTrue(p.rename('_hero', force=True))
		self.assertTrue(p.name.startswith('_hero_'))
		self.assertTrue(p.rename(''))
		self.assertNotIn(p.name, ('pal', '_sidekick'))

	def test_comment(self):
		p = ptr('_table')
		self.assertEqual(p.comment, '')
		self.assertTrue(p.set_comment('shared', repeatable=True))
		self.assertEqual(p.comment, 'shared')
		p.comment = 'own'
		self.assertEqual(p.comment, 'own')
		p.comment = ''
		self.assertEqual(p.comment, 'shared')

	def test_location(self):
		self.assertEqual(ptr('_hero').segment, '__data')
		self.assertEqual(ptr('_add').segment, '__text')
		self.assertEqual(Pointer(0x10).segment, '')
		self.assertEqual(ptr('_hero').rva, sym('hero') - 0x100000000)
		self.assertTrue(ptr('_add').is_code)
		self.assertFalse(ptr('_hero').is_code)
		self.assertEqual((ptr('_compute') + 8).func, Func(sym('compute')))
		self.assertIsNone(ptr('_hero').func)

	def test_operators(self):
		a, b = Pointer(0x20), Pointer(0x10)
		self.assertEqual(a + 4, 0x24)
		self.assertEqual(a - b, 0x10)
		self.assertEqual(a.add(b).sub(4), 0x2c)
		self.assertEqual(sorted([a, b]), [b, a])
		self.assertEqual(len({ a, Pointer(0x20), b }), 2)
		self.assertEqual({ a : 1 }[Pointer(0x20)], 1)
		self.assertEqual(int(a), 0x20)
		self.assertEqual(hex(a), '0x20')
		self.assertEqual(repr(a), '*0x20')

class TestCode(harness.IDATestCase):

	def calls_in(self, name):
		func = Func(sym(name))
		return [insn for insn in disasm(func.start, func.end) if insn.is_call]

	def test_xrefs_to(self):
		refs = ptr('_add').xrefs_to()
		kinds = sorted(ref.kind for ref in refs)
		self.assertEqual(kinds.count('call'), 3)
		self.assertEqual(kinds.count('jump'), 1)
		self.assertIn('offset', kinds)
		self.assertTrue(all(ref.to == sym('add') for ref in refs))
		callers = { ref.func.name for ref in refs if ref.kind == 'call' }
		self.assertEqual(callers, { '_compute', '_dispatch' })
		jump = next(ref for ref in refs if ref.kind == 'jump')
		self.assertEqual(jump.func.name, '_tail_caller')
		self.assertTrue(jump.is_code)
		from_data = [ref for ref in refs if ref.func is None]
		self.assertTrue(from_data)
		self.assertFalse(any(ref.is_code for ref in from_data))

	def test_data_xrefs(self):
		kinds = { ref.kind for ref in ptr('_counter').xrefs_to() }
		self.assertIn('read', kinds)
		self.assertEqual({ ref.func.name for ref in ptr('_counter').xrefs_to() if ref.func }, { '_leaf' })

	def test_xrefs_from(self):
		call = self.calls_in('compute')[0]
		refs = Pointer(call.address).xrefs_from()
		self.assertEqual([(ref.kind, ref.to.addr) for ref in refs], [('call', sym('add'))])
		self.assertEqual(Pointer(sym('compute')).xrefs_from(), [])

	def test_xref_json(self):
		data = [ref.to_dict() for ref in ptr('_add').xrefs_to()]
		json.dumps(data)
		self.assertIn({ 'frm' : hex(self.calls_in('compute')[0].address), 'to' : hex(sym('add')), 'kind' : 'call', 'func' : '_compute' }, data)
		self.assertIn(None, [item['func'] for item in data])
		self.assertIn('kind=call', repr(ptr('_add').xrefs_to()[0]))
		self.assertEqual(len(set(ptr('_add').xrefs_to())), len(ptr('_add').xrefs_to()))

	def test_insn(self):
		first = Insn(sym('compute'))
		self.assertEqual(first.address, sym('compute'))
		self.assertEqual(first.size, 4)
		self.assertEqual(first.mnem, 'SUB')
		self.assertEqual(first.ops[0], 'SP')
		self.assertTrue(first.defined)
		self.assertEqual(len(first.ops), 3)
		self.assertTrue(first.text.startswith('SUB'))
		self.assertFalse(first.is_call)
		self.assertIsNone(first.target)
		self.assertIsNone(first.call_target)
		self.assertEqual(Insn('_compute'), first)
		with self.assertRaises(IDAError):
			Insn(sym('hero'))

	def test_undefined_bytes_decode_only_while_debugging(self):
		data = sym('hero')
		with self.assertRaises(IDAError):
			Insn(data)
		with mock.patch.object(compat, 'debugger_active', lambda: True):
			insn = Insn(data)
			self.assertEqual(insn.size, 4)
			self.assertFalse(insn.defined)
			self.assertEqual(insn.mnem, 'UDF')
			self.assertEqual(insn.ops, ['#1'])
			self.assertTrue(insn.text.startswith('UDF'))
			with self.assertRaises(IDAError):
				Insn(sym('narrow_text'))

	def test_split_operands(self):
		from ida_scripts.memory import split_operands
		self.assertEqual(split_operands('X29, X30, [SP,#0x20+var_s0]'), ['X29', 'X30', '[SP,#0x20+var_s0]'])
		self.assertEqual(split_operands(''), [])
		self.assertEqual(split_operands('X8'), ['X8'])

	def test_calls(self):
		calls = self.calls_in('compute')
		self.assertEqual([call.call_target.name for call in calls], ['_add', '_mul', '_leaf', '_add'])
		self.assertEqual(calls[0].target, sym('add'))
		self.assertEqual(calls[0].ops, ['_add'])
		indirect = self.calls_in('apply')
		self.assertEqual(len(indirect), 1)
		self.assertEqual(indirect[0].mnem, 'BLR')
		self.assertIsNone(indirect[0].target)
		self.assertIsNone(indirect[0].call_target)

	def test_tail_jump_is_not_a_call(self):
		func = Func(sym('tail_caller'))
		jumps = [insn for insn in disasm(func.start, func.end) if insn.target == sym('add')]
		self.assertEqual(len(jumps), 1)
		self.assertFalse(jumps[0].is_call)
		self.assertIsNone(jumps[0].call_target)

	def test_pointer_disasm(self):
		insns = ptr('_compute').disasm(3)
		self.assertEqual([insn.address for insn in insns], [sym('compute') + 4 * n for n in range(3)])
		self.assertEqual(len(ptr('_compute').disasm()), 1)
		self.assertEqual(ptr('_hero').disasm(4), [])

	def test_pointer_disasm_with_what_leads_up(self):
		compute = Func('_compute')
		insns = compute.insns
		call = next(n for n, insn in enumerate(insns) if insn.is_call)
		self.assertGreaterEqual(call, 3)
		self.assertEqual(ptr(insns[call].address).disasm(1, before=3), insns[call - 3:call + 1])
		self.assertEqual(ptr(insns[call].address).disasm(2, before=1), insns[call - 1:call + 2])
		self.assertEqual(ptr(insns[call].address).disasm(0, before=2), insns[call - 2:call])
		# Not past the start of the function.
		self.assertEqual(ptr(insns[call].address).disasm(1, before=100), insns[:call + 1])
		self.assertEqual(ptr(compute.start).disasm(1, before=5), insns[:1])
		self.assertEqual(ptr('_hero').disasm(1, before=3), [])

	def test_disasm_range(self):
		start, end = sym('add'), sym('leaf')
		insns = disasm(start, end)
		self.assertEqual(len(insns), (end - start) // 4)
		self.assertEqual(disasm('_add', '_leaf'), insns)
		self.assertEqual(disasm(sym('hero'), sym('hero') + 16), [])
		data = [insn.to_dict() for insn in insns]
		json.dumps(data)
		self.assertEqual(set(data[0]), { 'address', 'mnem', 'ops', 'text' })
		self.assertIn(hex(start), repr(insns[0]))

if __name__ == '__main__':
	harness.main()
