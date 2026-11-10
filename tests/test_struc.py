''' Struct types on the 9.x type API: declaring, editing, reading and writing instances, and what the decompiler sees. '''

import json
import os
import shutil
import struct
import tempfile
from unittest import mock

import harness
from harness import sym
from test_memory import FakeProcess
from ida_scripts import compat
from ida_scripts import struc
from ida_scripts.utils import IDAError, DebuggerError
from ida_scripts.memory import Pointer, ptr
from ida_scripts.func import Func, CItem
from ida_scripts.struc import MemberT, StrucT, StrucI, parse_declaration, apply_prototypes, defined_names
import ida_typeinf
import ida_hexrays

with open(os.path.join(harness.TESTS, 'fixtures', 'sample.c')) as file:
	SAMPLE = file.read()
# struct Vec2 and struct Player, as the fixture defines them
PLAYER_C = SAMPLE[SAMPLE.index('struct Vec2 {'):SAMPLE.index('int counter')]

# offsetof and sizeof in the fixture, as clang lays struct Player out for arm64
PLAYER_LAYOUT = [('id', 0, 4), ('level', 4, 2), ('flags', 6, 1), ('name', 7, 16), ('position', 24, 8), ('score', 32, 8), ('title', 40, 8), ('inventory', 48, 16), ('next', 64, 8)]

PROTOTYPE = 'int __fastcall player_power(struct Player *player)'

def layout(s: StrucT) -> list:
	return [(m.name, m.offset, m.size) for m in s.members]

def gaps(s: StrucT) -> list:
	return [(m.name, m.offset, m.size, m.is_gap) for m in s.members]

class TestDeclare(harness.IDATestCase):

	fresh = True

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.declared = StrucT.parse(PLAYER_C)
		cls.player = StrucT.find('Player')

	def test_parse_gives_the_declared_structs(self):
		self.assertEqual([s.name for s in self.declared], ['Vec2', 'Player'])
		self.assertEqual(self.declared[1], self.player)
		self.assertEqual(self.declared[0].size, 8)
		self.assertEqual([(m.name, str(m.dtype)) for m in self.declared[0].members], [('x', 'float'), ('y', 'float')])

	def test_layout_matches_the_binary(self):
		self.assertEqual(layout(self.player), PLAYER_LAYOUT)
		self.assertEqual(self.player.size, 72)
		# The linker put sidekick right before hero, so the distance is the size clang gave the struct.
		self.assertEqual(sym('hero') - sym('sidekick'), self.player.size)
		types = { m.name : str(m.dtype) for m in self.player.members }
		self.assertEqual(types['name'], 'char[16]')
		self.assertEqual(types['position'], 'struct Vec2')
		self.assertEqual(types['next'], 'struct Player *')
		self.assertTrue(all(m.struct == self.player for m in self.player.members))

	def test_members_by_name_and_offset(self):
		level = self.player['level']
		self.assertIsInstance(level, MemberT)
		self.assertEqual((level.name, level.offset, level.size), ('level', 4, 2))
		self.assertEqual((level.udm.offset, level.udm.size), (32, 16))
		self.assertIsNone(self.player['nope'])
		self.assertEqual(self.player.member_at_offset(10).name, 'name')
		self.assertEqual(self.player.member_at_offset(7).name, 'name')
		self.assertEqual(self.player.member_at_offset(71).name, 'next')
		# 23 is padding before position, which IDA does not show as a member.
		for offset in (23, 72, 1000, -1):
			self.assertIsNone(self.player.member_at_offset(offset))
		self.assertEqual(self.player.member_starting_at_offset(7).name, 'name')
		self.assertIsNone(self.player.member_starting_at_offset(8))

	def test_find(self):
		for name in ('Player', 'struct Player', ' const struct Player '):
			self.assertEqual(StrucT.find(name), self.player)
		for name in ('nope', '', 'struct', 'uint32_t', 'mach_header_64 *'):
			self.assertIsNone(StrucT.find(name))
		self.assertEqual(StrucT.find('mach_header_64').size, 32)

	def test_construct(self):
		for target in ('Player', self.player.id, self.player.tif):
			self.assertEqual(StrucT(target), self.player)
		self.assertTrue(self.player.tif.is_struct())
		self.assertEqual(self.player.tif.get_size(), 72)
		for bad in ('nope', 0x1234, ida_typeinf.tinfo_t(ida_typeinf.BTF_INT)):
			with self.assertRaises(LookupError):
				StrucT(bad)

	def test_identity_and_json(self):
		vec2 = StrucT.find('Vec2')
		self.assertEqual(len({ self.player, StrucT('Player'), vec2 }), 2)
		self.assertNotEqual(self.player, vec2)
		self.assertNotEqual(self.player, self.player.id)
		self.assertEqual(repr(vec2), f'<StrucT id={hex(vec2.id)}, name=Vec2, size=8>')
		self.assertEqual(json.loads(json.dumps(vec2.to_dict())), { 'id' : hex(vec2.id), 'name' : 'Vec2', 'size' : 8 })
		level = self.player['level']
		self.assertEqual(level, self.player.member_at_offset(5))
		self.assertNotEqual(level, self.player['id'])
		self.assertEqual(len({ level, self.player['level'], self.player['id'] }), 2)
		self.assertIn('name=level', repr(level))
		self.assertEqual(json.loads(json.dumps(level.to_dict())), { 'id' : hex(level.id), 'name' : 'level', 'dtype' : '__int16', 'offset' : '0x4', 'size' : 2 })

	def test_declaration_round_trip(self):
		text = self.player.declaration
		self.assertTrue(text.startswith('struct Player'))
		self.assertIn('char name[16];', text)
		self.assertTrue(text.endswith('};'))
		self.assertEqual(StrucT.parse(text), [self.player])
		self.assertEqual(layout(self.player), PLAYER_LAYOUT)

	def test_typedef_union_and_other_types(self):
		parsed = StrucT.parse('''
			typedef struct { int a; char b; } Anon_t;
			union Number { int i; float f; };
			typedef int count_t;
			enum Mode { MODE_OFF };
		''')
		self.assertEqual(len(parsed), 2)
		anon, number = parsed
		self.assertEqual(StrucT.find('Anon_t'), anon)
		self.assertEqual(layout(anon), [('a', 0, 4), ('b', 4, 1)])
		self.assertTrue(anon.tif.is_struct())
		self.assertEqual(number.name, 'Number')
		self.assertTrue(number.tif.is_union())
		self.assertEqual(layout(number), [('i', 0, 4), ('f', 0, 4)])
		self.assertIsNone(StrucT.find('count_t'))
		self.assertIsNone(StrucT.find('Mode'))
		self.assertEqual(StrucT.parse('typedef int other_t;'), [])
		self.assertEqual(StrucT.parse(''), [])
		self.assertEqual([s.name for s in StrucT.parse('struct NoSemicolon { int a; }')], ['NoSemicolon'])

	def test_redefinition(self):
		held = StrucT.find('Player')
		renamed = PLAYER_C.replace('short level;', 'short rank;')
		self.assertEqual(StrucT.parse(renamed), [StrucT.find('Vec2'), held])
		self.assertEqual(held['rank'].offset, 4)
		self.assertIsNone(held['level'])
		self.assertEqual(StrucT.parse(PLAYER_C), [StrucT.find('Vec2'), held])
		self.assertEqual(layout(held), PLAYER_LAYOUT)

	def test_parse_error(self):
		with self.assertRaisesRegex(IDAError, r'cannot parse the declaration: \d+ errors?'):
			StrucT.parse('struct Broken { no_such_type_t x; };')
		self.assertIsNone(StrucT.find('Broken'))
		with self.assertRaises(IDAError):
			StrucT.parse('struct { int a')

	def test_parse_error_has_ida_messages(self):
		# idalib has no output window, so a fake one stands in for the GUI's: only collecting the messages is tested.
		window = ['earlier line']
		real_parse = ida_typeinf.parse_decls
		def parse_decls(til, text, printer, flags):
			if printer is True:
				window[:0] = ['Total 1 errors', 'Syntax error near: no_such_type_t']
			return real_parse(til, text, None, flags)
		with mock.patch.object(struc.ida_kernwin, 'msg_get_lines', lambda count: list(window)), mock.patch.object(struc.ida_typeinf, 'parse_decls', parse_decls):
			with self.assertRaises(IDAError) as caught:
				StrucT.parse('struct Broken2 { no_such_type_t x; };')
		self.assertRegex(str(caught.exception), r'^cannot parse the declaration: \d+ errors?\nSyntax error near: no_such_type_t\nTotal 1 errors$')

	def test_import_header(self):
		folder = tempfile.mkdtemp(prefix='ida_scripts_struc_')
		self.addCleanup(shutil.rmtree, folder, True)
		header = os.path.join(folder, 'things.h')
		with open(header, 'w') as file:
			file.write('/* a header */\n#define COUNT 4\nstruct HeaderThing { int values[COUNT]; struct Player *owner; };\ntypedef unsigned int header_id_t;\n')
		self.assertEqual(StrucT.import_header(header), 2)
		thing = StrucT.find('HeaderThing')
		self.assertEqual(layout(thing), [('values', 0, 16), ('owner', 16, 8)])
		self.assertEqual(StrucT.import_header(header), 0)
		broken = os.path.join(folder, 'broken.h')
		with open(broken, 'w') as file:
			file.write('struct HeaderBroken { no_such_type_t x; };\n')
		with self.assertRaisesRegex(IDAError, 'broken.h'):
			StrucT.import_header(broken)
		with self.assertRaisesRegex(IDAError, 'no such file'):
			StrucT.import_header(os.path.join(folder, 'missing.h'))

	def test_defined_names(self):
		text = '''
			#pragma pack(push, 1)
			// struct Commented { int a; };
			/* struct AlsoCommented { int a; }; */
			struct Plain { int a; };
			struct Ref { struct Plain *p; };
			struct Forward;
			typedef struct Tagged { int t; } Alias;
			typedef struct { int u; } *PAnon, Anon;
			struct __fixed(0x10) Fixed { int f; };
			struct __cppobj Derived : Plain { int d; };
			struct Outer { struct { short s; } inner; union { int i; } either; };
			enum Ignored { IGNORED };
		'''
		self.assertEqual(defined_names(text), ['Plain', 'Ref', 'Tagged', 'PAnon', 'Anon', 'Fixed', 'Derived', 'Outer'])

class TestEdit(harness.IDATestCase):

	fresh = True

	def test_create(self):
		s = StrucT.create('Fresh')
		self.assertEqual((s.name, s.size, s.members), ('Fresh', 0, []))
		self.assertEqual(StrucT.find('Fresh'), s)
		self.assertEqual(StrucT.add_struc('FreshToo').name, 'FreshToo')
		self.assertEqual(StrucT.create_struc('FreshThree').name, 'FreshThree')
		with self.assertRaisesRegex(IDAError, 'exists'):
			StrucT.create('Fresh')
		with self.assertRaisesRegex(IDAError, 'not acceptable'):
			StrucT.create('1 bad name')

	def test_add_and_delete_member(self):
		s = StrucT.create('Edited')
		held = StrucT.find('Edited')
		count = s.add_member('int count', 0)
		self.assertEqual((count.name, count.offset, count.size, str(count.dtype)), ('count', 0, 4, 'int'))
		self.assertEqual(count.struct, s)
		s.add_member('char label[8]', 4)
		s.add_member('double ratio', 16)
		self.assertEqual(layout(held), [('count', 0, 4), ('label', 4, 8), ('ratio', 16, 8)])
		self.assertEqual(held.size, 24)
		self.assertEqual(s.tif.get_size(), 24)
		# IDA takes 12..16 for the padding that aligns the double, not for a gap.
		self.assertIsNone(held.member_at_offset(13))
		with self.assertRaisesRegex(IDAError, 'overlaps'):
			s.add_member('int clash', 18)
		with self.assertRaisesRegex(IDAError, 'duplicate'):
			s.add_member('int count', 24)
		with self.assertRaisesRegex(IDAError, 'cannot parse'):
			s.add_member('no_such_type_t x', 24)
		self.assertEqual(held.size, 24)
		label, ratio = held['label'], held['ratio']
		self.assertTrue(s.delete_member(label))
		self.assertEqual(gaps(held), [('count', 0, 4, False), ('gap4', 4, 12, True), ('ratio', 16, 8, False)])
		# IDA gave the deleted member's id to the gap left in its place.
		self.assertEqual(label.name, 'gap4')
		self.assertEqual((count.name, count.offset), ('count', 0))
		self.assertEqual((ratio.name, ratio.offset), ('ratio', 16))
		self.assertTrue(s.delete_member('ratio'))
		self.assertEqual(layout(held), [('count', 0, 4)])
		self.assertEqual(held.size, 4)
		with self.assertRaisesRegex(IDAError, 'no longer exists'):
			ratio.offset
		self.assertFalse(s.delete_member(ratio))
		self.assertFalse(s.delete_member('nope'))
		self.assertFalse(StrucT.create('Other').delete_member(count))
		self.assertEqual(layout(held), [('count', 0, 4)])

	def test_deleted_type(self):
		doomed = StrucT.create('Doomed')
		member = doomed.add_member('int a', 0)
		self.assertTrue(ida_typeinf.del_named_type(None, 'Doomed', ida_typeinf.NTF_TYPE))
		self.assertIsNone(StrucT.find('Doomed'))
		self.assertEqual(doomed.name, '')
		for read in (lambda: doomed.tif, lambda: doomed.members, lambda: doomed.size, lambda: member.offset):
			with self.assertRaisesRegex(IDAError, 'no longer exists'):
				read()

	def test_add_gap(self):
		s = StrucT.create('Gapped')
		gap = s.add_gap(0, 16)
		self.assertEqual((gap.name, str(gap.dtype), gap.offset, gap.size, gap.is_gap), ('gap0', '_BYTE[16]', 0, 16, True))
		self.assertEqual(s.size, 16)
		self.assertEqual(s.add_gap(0, 16), gap)
		s.add_member('int last', 16)
		with self.assertRaisesRegex(IDAError, 'last is in the way'):
			s.add_gap(14, 4)
		self.assertEqual(gaps(s), [('gap0', 0, 16, True), ('last', 16, 4, False)])
		self.assertEqual(s.add_gap(20, 4).offset, 20)
		self.assertEqual(s.size, 24)

	def test_is_gap(self):
		s = StrucT.parse('struct GapKinds { char gap0[4]; int gapless; char spare[4]; _BYTE gap1C; };')[0]
		self.assertEqual({ m.name : m.is_gap for m in s.members }, { 'gap0' : True, 'gapless' : False, 'spare' : False, 'gap1C' : True })

	def test_add_member_auto(self):
		s = StrucT.create('Auto')
		held = StrucT.find('Auto')
		s.add_gap(0, 32)
		a = s.add_member_auto('int a', 0)
		self.assertEqual((a.name, a.offset), ('a', 0))
		self.assertEqual(gaps(held), [('a', 0, 4, False), ('gap4', 4, 28, True)])
		b = s.add_member_auto('int b', 12)
		self.assertEqual((b.name, b.offset), ('b', 12))
		self.assertEqual(gaps(held), [('a', 0, 4, False), ('gap4', 4, 8, True), ('b', 12, 4, False), ('gap10', 16, 16, True)])
		s.add_member_auto('int c', 28)
		self.assertEqual(gaps(held), [('a', 0, 4, False), ('gap4', 4, 8, True), ('b', 12, 4, False), ('gap10', 16, 12, True), ('c', 28, 4, False)])
		self.assertEqual(held.size, 32)
		# gap4 is now a gap IDA keeps itself, the member goes in all the same
		s.add_member_auto('short d', 6)
		self.assertEqual(gaps(held)[1:4], [('gap4', 4, 2, True), ('d', 6, 2, False), ('gap8', 8, 4, True)])
		before = held.declaration
		with self.assertRaisesRegex(IDAError, 'b is in the way'):
			s.add_member_auto('int e', 13)
		with self.assertRaisesRegex(IDAError, 'c is in the way'):
			s.add_member_auto('double e', 24)
		with self.assertRaisesRegex(IDAError, 'cannot parse'):
			s.add_member_auto('no_such_type_t e', 20)
		self.assertEqual(held.declaration, before)
		f = s.add_member_auto('int f', 40)
		self.assertEqual(gaps(held)[-2:], [('gap20', 32, 8, True), ('f', 40, 4, False)])
		self.assertEqual(f.struct.size, 44)

	def test_add_member_auto_as_flowers_does(self):
		s = StrucT.parse('struct overall_state { int head; char gap4[60]; int tail; };')[0]
		member = s.member_at_offset(0x14)
		self.assertTrue(member.is_gap)
		self.assertEqual(member.struct, s)
		offset = 0x10 + member.offset
		added = member.struct.add_member_auto(f'int int{hex(offset)[2:].upper()}', offset)
		self.assertEqual(added.name, 'int14')
		self.assertEqual(gaps(s), [('head', 0, 4, False), ('gap4', 4, 16, True), ('int14', 20, 4, False), ('gap18', 24, 40, True), ('tail', 64, 4, False)])

	def test_parse_declaration(self):
		for text, kind, name in (
			('unsigned int count[4]', 'unsigned int[4]', 'count'),
			('char name[16];', 'char[16]', 'name'),
			('int _under', 'int', '_under'),
			('_BYTE gap4[8]', '_BYTE[8]', 'gap4'),
			('void *where', 'void *', 'where'),
			('int (*callback)(int)', 'int (__fastcall *)(int)', 'callback'),
		):
			tif, found = parse_declaration(text)
			self.assertEqual((str(tif), found), (kind, name))
		for bad in ('int', 'no_such_type_t x', 'int 9x', '', 'int f(int)'):
			with self.assertRaisesRegex(IDAError, 'cannot parse'):
				parse_declaration(bad)

class TestInstance(harness.IDATestCase):

	fresh = True

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		StrucT.parse(PLAYER_C)
		cls.player = StrucT.find('Player')

	def test_hero(self):
		hero = self.player.instance_at('_hero')
		self.assertEqual(hero.addr, sym('hero'))
		self.assertEqual(hero['id'], 1)
		self.assertEqual(hero['level'], 42)
		self.assertEqual(hero['flags'], 0x80)
		self.assertEqual(hero['name'], b'hero' + bytes(12))
		position = hero['position']
		self.assertIsInstance(position, StrucI)
		self.assertEqual(position.struc_t, StrucT.find('Vec2'))
		self.assertEqual(position.addr, sym('hero') + 24)
		self.assertEqual((position['x'], position['y']), (1.0, 2.0))
		self.assertEqual(hero['score'], 99.5)
		self.assertIsInstance(hero['title'], Pointer)
		self.assertEqual(hero['title'].string(), 'the first')
		self.assertEqual(hero['inventory'], [1, 2, 3, 4])
		self.assertIsInstance(hero['next'], Pointer)
		self.assertEqual(hero['next'], sym('sidekick'))

	def test_sidekick(self):
		sidekick = StrucI(sym('sidekick'), 'Player')
		self.assertEqual(sidekick.members, {
			'id' : 2, 'level' : 3, 'flags' : 1, 'name' : b'sidekick' + bytes(8), 'position' : StrucI(sym('sidekick') + 24, 'Vec2'),
			'score' : 12.5, 'title' : sidekick['title'], 'inventory' : [5, 6, 7, 8], 'next' : Pointer(0),
		})
		self.assertEqual(sidekick['position'].members, { 'x' : 0.5, 'y' : -0.5 })
		self.assertEqual(sidekick['title'].string(), 'the second')
		self.assertEqual(self.player.instance_at('_hero')['next'].addr, sidekick.addr.addr)

	def test_to_dict(self):
		data = json.loads(json.dumps(self.player.instance_at('_hero').to_dict()))
		self.assertEqual(list(data), [name for name, _, _ in PLAYER_LAYOUT])
		self.assertEqual(data['position'], { 'x' : 1.0, 'y' : 2.0 })
		self.assertEqual(data['next'], hex(sym('sidekick')))
		self.assertEqual(data['name'], 'hero')
		self.assertEqual(data['inventory'], [1, 2, 3, 4])

	def test_member_and_ptr(self):
		hero = self.player.instance_at(Pointer(sym('hero')))
		self.assertEqual(hero.member('score'), sym('hero') + 32)
		self.assertIsInstance(hero.member('score'), Pointer)
		self.assertEqual(hero.member('score', return_pointer=False), 99.5)
		self.assertIsNone(hero.member('nope'))
		self.assertEqual(hero.ptr('inventory'), sym('hero') + 48)
		self.assertEqual(hero.ptr('inventory').array('i', 2), [1, 2])
		with self.assertRaises(KeyError):
			hero['nope']
		with self.assertRaises(KeyError):
			hero.ptr('nope')
		with self.assertRaises(KeyError):
			hero['nope'] = 1

	def test_member_type_reads(self):
		score = self.player['score']
		self.assertEqual(score.instance_at(sym('hero') + 32), 99.5)
		self.assertEqual(score.instance_at_struct('_hero'), 99.5)
		self.assertEqual(score.instance_at_struct(Pointer(sym('sidekick'))), 12.5)
		self.assertEqual(self.player['next'].instance_at_struct(sym('hero')), sym('sidekick'))
		with self.assertRaises(IDAError):
			score.instance_at(0x10)

	def test_identity(self):
		hero = self.player.instance_at('_hero')
		self.assertEqual(hero, StrucI('_hero', 'Player'))
		self.assertEqual(len({ hero, StrucI(sym('hero'), self.player), StrucI('_sidekick', 'Player'), StrucI('_hero', 'Vec2') }), 3)
		self.assertNotEqual(hero, StrucI('_hero', 'Vec2'))
		self.assertNotEqual(hero, sym('hero'))
		self.assertEqual(repr(hero), f'<StrucI addr=*{hex(hero.addr.addr)}, struc_t={self.player!r}>')
		with self.assertRaises(LookupError):
			StrucI('_hero', 'nope')

KINDS_C = '''
enum Mode { MODE_OFF = 0, MODE_ON = 2 };
struct Pair { short a; short b; };
struct Kinds {
	char c;
	unsigned char uc;
	_BYTE raw;
	bool flag;
	enum Mode mode;
	_DWORD dw;
	__int128 big;
	float f;
	double d;
	unsigned short us;
	char text[4];
	unsigned char data[3];
	_BYTE blob[2];
	short shorts[3];
	float floats[2];
	void *ptrs[2];
	struct Pair pairs[2];
	char grid[2][3];
	unsigned int lo : 3;
	int mid : 5;
	unsigned int hi : 24;
};
'''

class TestValueKinds(harness.IDATestCase):

	fresh = True
	base = 0x7000

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.kinds = StrucT.parse(KINDS_C)[-1]

	def setUp(self):
		values = {
			'c' : b'\xff', 'uc' : b'\xfe', 'raw' : b'\x7f', 'flag' : b'\x01', 'mode' : struct.pack('<i', 2), 'dw' : struct.pack('<I', 0xDEADBEEF),
			'big' : (-5).to_bytes(16, 'little', signed=True), 'f' : struct.pack('<f', 1.5), 'd' : struct.pack('<d', -2.25), 'us' : b'\xff\xff',
			'text' : b'abc\x00', 'data' : b'\x01\x02\x03', 'blob' : b'\xaa\xbb', 'shorts' : struct.pack('<3h', -1, 2, -3),
			'floats' : struct.pack('<2f', 0.5, 4.0), 'ptrs' : struct.pack('<2Q', 0x1000, 0), 'pairs' : struct.pack('<4h', 1, -2, 3, 4), 'grid' : b'xy\x00zw\x00',
		}
		data = bytearray(self.kinds.size)
		for name, raw in values.items():
			offset = self.kinds[name].offset
			data[offset:offset + len(raw)] = raw
		whole = int.from_bytes(data, 'little')
		for name, value in (('lo', 5), ('mid', -3), ('hi', 0xABCDEF)):
			udm = self.kinds[name].udm
			whole |= (value & ((1 << udm.size) - 1)) << udm.offset
		self.process = FakeProcess(self.base, whole.to_bytes(len(data), 'little'))
		patcher = self.process.attach()
		patcher.start()
		self.addCleanup(patcher.stop)
		self.instance = self.kinds.instance_at(self.base)

	def test_scalars(self):
		i = self.instance
		self.assertEqual((i['c'], i['uc'], i['raw'], i['us']), (-1, 254, 127, 65535))
		self.assertIs(i['flag'], True)
		self.assertEqual(i['mode'], 2)
		self.assertEqual(i['dw'], 0xDEADBEEF)
		self.assertEqual(i['big'], -5)
		self.assertEqual((i['f'], i['d']), (1.5, -2.25))

	def test_arrays(self):
		i = self.instance
		self.assertEqual((i['text'], i['data'], i['blob']), (b'abc\x00', b'\x01\x02\x03', b'\xaa\xbb'))
		self.assertEqual(i['shorts'], [-1, 2, -3])
		self.assertEqual(i['floats'], [0.5, 4.0])
		self.assertEqual(i['ptrs'], [Pointer(0x1000), Pointer(0)])
		self.assertTrue(all(isinstance(p, Pointer) for p in i['ptrs']))
		pairs = i['pairs']
		self.assertEqual([p.addr for p in pairs], [self.base + self.kinds['pairs'].offset + 4 * n for n in range(2)])
		self.assertEqual([p.members for p in pairs], [{ 'a' : 1, 'b' : -2 }, { 'a' : 3, 'b' : 4 }])
		self.assertEqual(i['grid'], [b'xy\x00', b'zw\x00'])

	def test_bitfields(self):
		lo, mid, hi = self.kinds['lo'], self.kinds['mid'], self.kinds['hi']
		# lo and mid share a byte, hi does not fit in what is left of their 32-bit unit and starts the next one
		self.assertEqual((mid.udm.offset, mid.offset), (lo.udm.offset + 3, lo.offset))
		self.assertEqual(hi.udm.offset % 32, 0)
		self.assertEqual(hi.offset, hi.udm.offset // 8)
		self.assertEqual((lo.size, mid.size, hi.size), (1, 1, 3))
		self.assertEqual((self.instance['lo'], self.instance['mid'], self.instance['hi']), (5, -3, 0xABCDEF))
		self.assertTrue(self.instance.__setitem__('mid', 15))
		self.assertEqual((self.instance['lo'], self.instance['mid'], self.instance['hi']), (5, 15, 0xABCDEF))
		self.instance['mid'] = -16
		self.instance['lo'] = 0
		self.instance['hi'] = 1
		self.assertEqual((self.instance['lo'], self.instance['mid'], self.instance['hi']), (0, -16, 1))
		self.instance['mid'] = 0b10001
		self.assertEqual(self.instance['mid'], -15)
		for bad in (32, -17):
			with self.assertRaises(ValueError):
				self.instance['mid'] = bad
		with self.assertRaises(TypeError):
			self.instance['lo'] = 1.5

	def test_members_read_once(self):
		reads = []
		real = compat.dbg_read
		with mock.patch.object(compat, 'dbg_read', lambda ea, size: reads.append(size) or real(ea, size)):
			members = self.instance.members
		self.assertEqual(reads, [self.kinds.size])
		self.assertEqual(members['big'], -5)
		self.assertEqual(members['hi'], 0xABCDEF)
		json.dumps(self.instance.to_dict())

	def test_writes(self):
		i = self.instance
		i['flag'] = False
		i['mode'] = 0
		i['big'] = -(1 << 127)
		i['c'] = 0x80
		i['ptrs'] = [Pointer(0x2000)]
		i['pairs'] = [b'\x07\x00\x08\x00']
		i['grid'] = [b'ab', 'cd']
		i['floats'] = (1, 2.5)
		self.assertIs(i['flag'], False)
		self.assertEqual((i['mode'], i['big'], i['c']), (0, -(1 << 127), -128))
		self.assertEqual(i['ptrs'], [Pointer(0x2000), Pointer(0)])
		self.assertEqual(i['pairs'][0].members, { 'a' : 7, 'b' : 8 })
		self.assertEqual(i['grid'], [b'ab\x00', b'cd\x00'])
		self.assertEqual(i['floats'], [1.0, 2.5])
		self.assertEqual(i['lo'], 5)

class TestWrite(harness.IDATestCase):

	fresh = True

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		StrucT.parse(PLAYER_C)
		cls.player = StrucT.find('Player')
		cls.memory = ptr('_sidekick').read(2 * cls.player.size)

	def setUp(self):
		self.process = FakeProcess(sym('sidekick'), self.memory)
		patcher = self.process.attach()
		patcher.start()
		self.addCleanup(patcher.stop)
		self.hero = StrucI('_hero', 'Player')

	def raw(self, name: str) -> bytes:
		member = self.player[name]
		start = sym('hero') - sym('sidekick') + member.offset
		return bytes(self.process.data[start:start + member.size])

	def test_reads_come_from_the_process(self):
		self.assertEqual(self.hero['level'], 42)
		self.process.data[72 + 4:72 + 6] = struct.pack('<h', -7)
		self.assertEqual(self.hero['level'], -7)
		self.assertEqual(self.hero.members['level'], -7)

	def test_integers(self):
		self.assertTrue(self.hero.__setitem__('id', 7))
		self.assertEqual(self.raw('id'), struct.pack('<i', 7))
		self.assertEqual(self.hero['id'], 7)
		self.hero['level'] = -2
		self.assertEqual(self.hero['level'], -2)
		self.hero['level'] = 0xFFFF
		self.assertEqual(self.hero['level'], -1)
		self.hero['flags'] = 0x81
		self.assertEqual(self.hero['flags'], 0x81)
		self.hero['id'] = b'\x05\x00\x00\x00'
		self.assertEqual(self.hero['id'], 5)
		for name, bad in (('id', 1 << 32), ('level', -40000), ('flags', 256)):
			with self.assertRaises(ValueError):
				self.hero[name] = bad
		with self.assertRaises(ValueError):
			self.hero['id'] = b'\x01'
		with self.assertRaises(TypeError):
			self.hero['id'] = 'seven'
		self.assertEqual(self.hero['id'], 5)

	def test_floats_and_nested(self):
		self.hero['score'] = 1.25
		self.assertEqual(self.raw('score'), struct.pack('<d', 1.25))
		self.hero['position'] = { 'x' : 3.0 }
		self.assertEqual(self.hero['position'].members, { 'x' : 3.0, 'y' : 2.0 })
		self.hero['position'] = StrucI('_sidekick', 'Player')['position']
		self.assertEqual(self.hero['position'].members, { 'x' : 0.5, 'y' : -0.5 })
		with self.assertRaises(KeyError):
			self.hero['position'] = { 'z' : 1.0 }
		with self.assertRaises(TypeError):
			self.hero['score'] = 'high'
		with self.assertRaises(TypeError):
			self.hero['position'] = 1.0

	def test_arrays(self):
		self.hero['name'] = 'boss'
		self.assertEqual(self.hero['name'], b'boss' + bytes(12))
		self.hero['name'] = b'ab'
		self.assertEqual(self.raw('name'), b'ab' + bytes(14))
		with self.assertRaises(ValueError):
			self.hero['name'] = 'x' * 17
		self.assertEqual(self.hero['name'], b'ab' + bytes(14))
		self.hero['inventory'] = [9, 8]
		self.assertEqual(self.hero['inventory'], [9, 8, 3, 4])
		with self.assertRaises(ValueError):
			self.hero['inventory'] = [1, 2, 3, 4, 5]
		with self.assertRaises(TypeError):
			self.hero['inventory'] = 5

	def test_pointers(self):
		self.hero['next'] = Pointer(0x1234)
		self.assertEqual(self.hero['next'], 0x1234)
		self.hero['next'] = '_hero'
		self.assertEqual(self.hero['next'], sym('hero'))
		self.hero['title'] = 0
		self.assertEqual(self.raw('title'), bytes(8))
		with self.assertRaises(LookupError):
			self.hero['next'] = 'no_such_symbol'

	def test_failed_write(self):
		self.process.writable = False
		self.assertFalse(self.hero.__setitem__('id', 1))
		self.assertEqual(self.hero['id'], 1)

	def test_needs_a_process(self):
		with mock.patch.object(compat, 'debugger_active', lambda: False):
			self.assertEqual(self.hero['level'], 42)
			with self.assertRaises(DebuggerError):
				self.hero['level'] = 1
			with self.assertRaises(DebuggerError):
				self.hero['position'] = { 'x' : 1.0 }

class MemptrVisitor(ida_hexrays.ctree_visitor_t):

	def __init__(self):
		ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
		self.items = []

	def visit_expr(self, expr):
		if expr.op == ida_hexrays.cot_memptr:
			self.items.append(expr)
		return 0

class TestPseudocode(harness.IDATestCase):

	fresh = True

	def test_prototype_and_struct_reach_the_pseudocode(self):
		power = Func('_player_power')
		before = power.decompile().pseudocode
		self.assertNotIn('->level', before)
		StrucT.parse(PLAYER_C)
		player = StrucT.find('Player')
		# The compiled code reads level, inventory[1] and score at these offsets.
		for offset in (player['level'].offset, player['inventory'].offset + 4, player['score'].offset):
			self.assertRegex(before, rf'\+ {offset}\)')
		self.assertEqual(apply_prototypes({ power.start : PROTOTYPE }), 1)
		self.assertEqual(power.prototype, PROTOTYPE)
		after = power.decompile().pseudocode
		for access in ('player->level', 'player->inventory[1]', 'player->score'):
			self.assertIn(access, after)
		StrucT.parse(PLAYER_C.replace('short level;', 'short rank;'))
		self.assertIn('player->rank', power.decompile().pseudocode)

class TestDecompiler(harness.IDATestCase):

	fresh = True

	def test_changes_drop_cached_pseudocode(self):
		power = Func('_player_power')
		s = StrucT.create('Cached')
		folder = tempfile.mkdtemp(prefix='ida_scripts_struc_')
		self.addCleanup(shutil.rmtree, folder, True)
		header = os.path.join(folder, 'cached.h')
		with open(header, 'w') as file:
			file.write('struct CachedHeader { int a; };\n')
		changes = [
			lambda: s.add_member('int a', 0),
			lambda: s.add_gap(4, 8),
			lambda: s.add_member_auto('int b', 8),
			lambda: s.delete_member('a'),
			lambda: StrucT.parse('struct CachedToo { int a; };'),
			lambda: StrucT.import_header(header),
			lambda: apply_prototypes({ '_leaf' : 'int __fastcall leaf(void)' }),
		]
		for change in changes:
			power.decompile()
			self.assertTrue(ida_hexrays.has_cached_cfunc(power.start))
			change()
			self.assertFalse(ida_hexrays.has_cached_cfunc(power.start))

	def test_apply_prototypes(self):
		self.assertEqual(apply_prototypes({}), 0)
		applied = apply_prototypes({
			'_add' : 'int __fastcall add(int left, int right)',
			Pointer(sym('mul')) : 'int __fastcall mul(int x, int y);',
			sym('leaf') + 4 : 'int __fastcall leaf(void)',
			sym('hero') : 'int hero(void)',
			'no_such_function' : 'int nope(void)',
			sym('compute') : 'this is not C',
		})
		self.assertEqual(applied, 3)
		self.assertEqual(list(Func('_add').arguments), ['left', 'right'])
		self.assertEqual(list(Func('_mul').arguments), ['x', 'y'])
		self.assertIn('left + right', Func('_add').decompile().pseudocode)
		self.assertNotIn('this', Func('_compute').prototype)

	def test_citem_finds_the_struct_and_member(self):
		StrucT.parse(PLAYER_C)
		self.assertEqual(apply_prototypes({ sym('player_power') : PROTOTYPE }), 1)
		cfunc = Func('_player_power').decompile()
		visitor = MemptrVisitor()
		visitor.apply_to(cfunc.decompiled.body, None)
		items = [CItem(expr, None) for expr in visitor.items]
		self.assertEqual({ item.accessed_struct for item in items }, { StrucT.find('Player') })
		members = { item.accessed_struct_member.name for item in items }
		self.assertEqual(members, { 'level', 'inventory', 'score' })
		self.assertFalse(any(item.accessed_struct_member.is_gap for item in items))

if __name__ == '__main__':
	harness.main()
