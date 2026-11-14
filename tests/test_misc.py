import json
import re
from unittest import mock

import harness
from harness import sym
from ida_scripts import compat
from ida_scripts import misc
from ida_scripts.memory import Pointer, ptr
from ida_scripts.func import Func
from ida_scripts.misc import *
import ida_bytes
import ida_name
import ida_nalt
import ida_strlist
import ida_typeinf

class TestNames(harness.IDATestCase):

	def test_find_symbol(self):
		self.assertEqual(find_symbol('_hero'), sym('hero'))
		self.assertIsInstance(find_symbol('_hero'), Pointer)
		self.assertEqual(find_symbol('_compute'), sym('compute'))
		self.assertIsNone(find_symbol('no_such_symbol'))
		# A C name finds the symbol that Mach-O gives a leading underscore.
		self.assertEqual(find_symbol('hero'), sym('hero'))
		self.assertEqual(find_symbol('compute'), sym('compute'))
		self.assertFalse(hasattr(misc, 'find_local_var'))

	def test_search_names(self):
		self.assertEqual(search_names('^_(add|mul)$'), [sym('add'), sym('mul')])
		self.assertEqual(search_names('_value$'), [sym(name) for name in ('small_value', 'big_value', 'single_value', 'double_value')])
		self.assertTrue(all(isinstance(p, Pointer) for p in search_names('_value$')))
		everything = search_names('')
		self.assertEqual(everything, sorted(everything))
		self.assertIn(Pointer('aHelloFixtureS'), everything)
		self.assertEqual(search_names('', limit=3), everything[:3])
		self.assertEqual(search_names('', limit=0), [])
		self.assertEqual(search_names('no_such_symbol'), [])
		# sub_ and loc_ names are made up when printed, not stored.
		self.assertEqual(search_names('^(sub|loc)_'), [])
		with self.assertRaises(re.error):
			search_names('[')

class TestComments(harness.IDATestCase):

	fresh = True

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls.insn = sym('compute') + 8
		cls.unexplored = sym('hero') + 1
		ida_bytes.set_cmt(cls.insn, 'needle in an instruction', False)
		ida_bytes.set_cmt(sym('table'), 'needle repeated', True)
		ida_bytes.set_cmt(cls.unexplored, 'needle in unexplored bytes', False)
		compat.set_func_comment(sym('leaf'), 'needle for a function', True)
		compat.set_func_comment(sym('mul'), 'regular needle for a function', False)

	def test_named_only(self):
		self.assertEqual(search_comments('needle'), [sym('mul'), sym('leaf'), sym('table')])
		self.assertEqual(search_comments('^regular'), [sym('mul')])
		self.assertEqual(search_comments('needle', limit=2), [sym('mul'), sym('leaf')])
		self.assertEqual(search_comments('no such comment'), [])
		# Comments that the Mach-O loader put on the header.
		self.assertEqual(search_comments('^Magic number$'), [0x100000000])

	def test_every_address(self):
		found = search_comments('needle', named_only=False)
		self.assertEqual(found, [sym('mul'), sym('leaf'), self.insn, sym('table'), self.unexplored])
		self.assertTrue(all(isinstance(p, Pointer) for p in found))
		self.assertEqual(search_comments('needle', limit=3, named_only=False), found[:3])
		self.assertEqual(search_comments('library', named_only=False), search_comments('library'))
		with self.assertRaises(re.error):
			search_comments('(', named_only=False)

class TestStrings(harness.IDATestCase):

	def test_list(self):
		found = strings()
		texts = { s.text : s for s in found }
		self.assertEqual([s.address for s in found], sorted(s.address for s in found))
		self.assertEqual(texts['hello fixture %s\n'].address, Pointer('aHelloFixtureS'))
		self.assertEqual(texts['pointer target'].address, Pointer('aPointerTarget'))
		self.assertEqual(texts['narrow fixture'].address, sym('narrow_text'))
		# UTF-16
		self.assertEqual(texts['wide fixture'].address, sym('wide_text'))
		self.assertTrue(all(isinstance(s, StringRef) for s in found))

	def test_funcs(self):
		texts = { s.text : s for s in strings() }
		self.assertEqual(texts['hello fixture %s\n'].funcs, [Func('_greet')])
		self.assertEqual(texts['wide fixture'].funcs, [Func('_main')])
		self.assertEqual(texts['pointer target'].funcs, [Func('_uses_strings')])
		# strlen(narrow_text) became a constant, and the header strings are referenced from data only.
		self.assertEqual(texts['narrow fixture'].funcs, [])
		self.assertEqual(texts['/usr/lib/dyld'].funcs, [])

	def test_pattern(self):
		self.assertEqual([s.text for s in strings('fixture')], ['wide fixture', 'narrow fixture', 'hello fixture %s\n'])
		self.assertEqual([s.text for s in strings('^pointer')], ['pointer target'])
		self.assertEqual(strings('no such string'), [])
		with self.assertRaises(re.error):
			strings('(')

	def test_json(self):
		data = json.loads(json.dumps([s.to_dict() for s in strings('fixture')]))
		self.assertEqual(data[2], { 'address' : hex(Pointer('aHelloFixtureS').addr), 'text' : 'hello fixture %s\n', 'funcs' : ['_greet'] })
		self.assertIn("funcs=['_greet']", repr(strings('hello')[0]))
		self.assertEqual(strings('hello'), strings('hello'))

	def test_the_list_is_built_once(self):
		from unittest import mock
		from ida_scripts import misc
		strings()
		with mock.patch.object(misc, 'build_string_list', side_effect=misc.build_string_list) as build:
			self.assertEqual(len(strings('fixture')), 3)
			self.assertEqual(build.call_count, 0)
			self.assertEqual(len(strings('fixture', refresh=True)), 3)
			self.assertEqual(build.call_count, 1)

	def test_options_are_restored(self):
		options = ida_strlist.get_strlist_options()
		before = (list(options.strtypes), options.only_7bit, options.minlen)
		strings(refresh=True)
		self.assertEqual((list(options.strtypes), options.only_7bit, options.minlen), before)
		self.assertEqual(before[:2], ([ida_nalt.STRTYPE_C], 1))

class TestStringEncodings(harness.IDATestCase):
	''' The fixture has a cp932 string and a UTF-8 one. IDA decodes them with the database's 8-bit encoding, set to cp932 here. '''

	fixture = 'misc_strings'
	fresh = True

	def test_utf8_database(self):
		# With the default UTF-8, IDA cannot read the cp932 bytes and only finds their ASCII tail.
		self.assertEqual([s.text for s in strings('cp932')], ['g cp932'])

	def test_with_the_database_encoding(self):
		index = ida_nalt.add_encoding('cp932')
		self.assertTrue(ida_nalt.set_default_encoding_idx(ida_nalt.BPU_1B, index))
		self.assertEqual([s.text for s in strings('cp932')], ['g cp932'], 'the list built before the change is kept')
		found = strings('cp932', refresh=True)
		self.assertEqual([(s.address, s.text) for s in found], [(sym('sjis_text'), 'テスト cp932')])
		self.assertEqual(found[0].funcs, [Func('_uses_sjis')])
		self.assertEqual(strings('cp932', encoding='cp932')[0].text, 'テスト cp932')
		self.assertEqual(strings('cp932', encoding='latin-1')[0].text, '\x83e\x83X\x83g cp932')
		# IDA reads the UTF-8 string as cp932, the encoding puts that right.
		self.assertEqual(strings('utf8')[0].text, 'cafﾃｩ utf8')
		self.assertEqual(strings('utf8', encoding='utf-8')[0].text, 'café utf8')
		# The pattern applies to the decoded text.
		self.assertEqual(strings('café', encoding='utf-8')[0].address, sym('utf8_text'))
		self.assertEqual(strings('café'), [])
		# UTF-16 strings keep their decoding.
		self.assertEqual([s.text for s in strings('utf16', encoding='latin-1')], ['utf16 marker'])
		# Referenced from a pointer in data, read by uses_plain, and as a literal by also_plain.
		self.assertEqual(strings('plain marker')[0].funcs, [Func('_uses_plain'), Func('_also_plain')])

class TestBulk(harness.IDATestCase):

	fresh = True

	def counting(self):
		''' Patch the decompiler refresh and the renaming in misc, to count the calls. '''
		refresh = mock.Mock(wraps=compat.refresh_decompiler)
		rename = mock.Mock(wraps=misc.set_name)
		patchers = [mock.patch.object(compat, 'refresh_decompiler', refresh), mock.patch.object(misc, 'set_name', rename)]
		for patcher in patchers:
			patcher.start()
			self.addCleanup(patcher.stop)
		return refresh, rename

	def test_rename_all(self):
		self.assertIn('mul(', Func('_dispatch').pseudocode())
		refresh, rename = self.counting()
		names = { sym('add') : 'sum2', hex(sym('mul')) : 'product', str(sym('leaf')) : 'read_counter', '_compute' : 'combine' }
		start = { 'compute' : sym('compute'), 'leaf' : sym('leaf') }
		self.assertEqual(rename_all(names), 4)
		self.assertEqual(rename.call_count, 4)
		self.assertEqual(refresh.call_count, 1)
		self.assertEqual([Func(start).name for start in (sym('sum2'), sym('product'), start['leaf'], start['compute'])], ['sum2', 'product', 'read_counter', 'combine'])
		self.assertIn('product(', Func('_dispatch').pseudocode())
		self.assertIn('read_counter()', Func('combine').pseudocode())
		# Unchanged names do not count.
		self.assertEqual(rename_all({ sym('sum2') : 'sum2' }), 0)
		# A taken name gets a number, unless force is off.
		self.assertEqual(rename_all({ sym('product') : 'sum2' }, force=False), 0)
		self.assertEqual(Func(sym('product')).name, 'product')
		self.assertEqual(rename_all({ sym('product') : 'sum2' }), 1)
		self.assertRegex(Func(sym('dispatch')).callees[1].name, r'^sum2_\d+$')

	def test_resolved_before_changing(self):
		with self.assertRaises(LookupError):
			rename_all({ sym('dispatch') : 'renamed_dispatch', 'no_such_symbol' : 'x' })
		self.assertEqual(Func(sym('dispatch')).name, '_dispatch')
		with self.assertRaises(LookupError):
			comment_all({ sym('dispatch') : 'text', 'no_such_symbol' : 'x' })
		self.assertEqual(Func('_dispatch').comment, '')

	def test_comment_all(self):
		refresh, _ = self.counting()
		self.assertEqual(comment_all({ sym('greet') : 'prints a greeting', '_table' : 'four numbers', sym('main') + 8 : 'in main' }), 3)
		self.assertEqual(refresh.call_count, 1)
		self.assertEqual(Func('_greet').comment, 'prints a greeting')
		self.assertEqual(ida_bytes.get_cmt(sym('table'), True), 'four numbers')
		self.assertEqual(ptr('_table').comment, 'four numbers')
		self.assertEqual(ida_bytes.get_cmt(sym('main') + 8, True), 'in main')
		self.assertEqual(ida_bytes.get_cmt(sym('main') + 8, False), None)
		# The decompiler shows the new function comment.
		self.assertEqual(Func('_greet').decompile().lines[0], '// prints a greeting')
		self.assertEqual(comment_all({ '_table' : 'four numbers' }), 0)
		self.assertEqual(comment_all({ '_greet' : 'regular one', '_table' : 'regular' }, repeatable=False), 2)
		self.assertEqual(compat.func_comment(sym('greet'), False), 'regular one')
		self.assertEqual(Func('_greet').comment, 'prints a greeting')
		self.assertEqual(ida_bytes.get_cmt(sym('table'), False), 'regular')
		self.assertEqual(comment_all({ '_table' : '' }, repeatable=False), 1)
		self.assertEqual(ida_bytes.get_cmt(sym('table'), False), None)

	def test_annotate_all(self):
		refresh, rename = self.counting()
		hero, sidekick = sym('hero'), sym('sidekick')
		items = { sym('uses_strings') : ('string_user', 'measures two strings'), hero : (None, 'the hero'), sidekick : ('buddy', None), sym('small_value') : (None, None) }
		self.assertEqual(annotate_all(items), 3)
		self.assertEqual(refresh.call_count, 1)
		self.assertEqual(rename.call_count, 2)
		self.assertEqual(Func(sym('string_user')).comment, 'measures two strings')
		self.assertEqual(ptr('_hero').comment, 'the hero')
		self.assertEqual(ptr('buddy'), sidekick)
		self.assertEqual(ptr('_small_value').comment, '')
		self.assertIn('string_user(', Func('_main').pseudocode())
		self.assertEqual(annotate_all({ hero : (None, 'the hero'), sidekick : ('buddy', None) }), 0)
		self.assertEqual(annotate_all({}), 0)

class TestAnnotations(harness.IDATestCase):

	fresh = True

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		with open(harness.TESTS + '/fixtures/sample.c') as file:
			source = file.read()
		assert ida_typeinf.parse_decls(None, source[source.index('struct Vec2'):source.index('int counter')], None, ida_typeinf.HTI_DCL) == 0
		cls.insn = sym('compute') + 8
		assert annotate_all({
			sym('add') : ('sum_two', 'adds two numbers'),
			sym('counter') : ('g_counter', None),
			Pointer('aPointerTarget').addr : ('str_pointer_target', None),
			sym('table') : (None, 'four numbers'),
			cls.insn : (None, 'repeated at the instruction'),
		}) == 5
		ida_bytes.set_cmt(cls.insn, 'third instruction', False)
		compat.set_func_comment(sym('leaf'), 'regular function comment', False)
		assert Func('sum_two').set_prototype('int __fastcall sum_two(int left, int right)')
		assert Func('_player_power').set_prototype('int player_power(struct Player *player)')

	def test_export(self):
		data = export_annotations()
		self.assertEqual(json.loads(json.dumps(data)), data)
		self.assertEqual(set(data), { 'names', 'comments', 'repeatable_comments', 'function_comments', 'repeatable_function_comments', 'prototypes', 'types' })
		self.assertEqual(data['names'][hex(sym('sum_two'))], 'sum_two')
		self.assertEqual(data['names'][hex(sym('g_counter'))], 'g_counter')
		self.assertEqual(data['names'][hex(Pointer('str_pointer_target').addr)], 'str_pointer_target')
		self.assertEqual(data['names'][hex(sym('main'))], '_main')
		# Names that IDA made up are not exported.
		self.assertNotIn(hex(Pointer('aHelloFixtureS').addr), data['names'])
		self.assertEqual(data['comments'][hex(self.insn)], 'third instruction')
		self.assertEqual(data['comments'][hex(0x100000000)], 'Magic number')
		self.assertEqual(data['repeatable_comments'][hex(self.insn)], 'repeated at the instruction')
		self.assertEqual(data['repeatable_comments'][hex(sym('table'))], 'four numbers')
		self.assertEqual(data['repeatable_function_comments'], { hex(sym('sum_two')) : 'adds two numbers' })
		self.assertEqual(data['function_comments'], { hex(sym('leaf')) : 'regular function comment' })
		self.assertEqual(data['prototypes'][hex(sym('sum_two'))], 'int __fastcall sum_two(int left, int right)')
		self.assertEqual(data['prototypes'][hex(sym('player_power'))], 'int __fastcall player_power(struct Player *player)')
		# Guessed types are not exported.
		self.assertNotIn(hex(sym('compute')), data['prototypes'])
		self.assertIn('struct Vec2\n{\n  float x;\n  float y;\n};', data['types'])
		self.assertTrue(data['types'][-1].startswith('struct Player\n{'))
		self.assertFalse(any(re.search(r'/\* \d+ \*/', text) for text in data['types']))

	def test_round_trip(self):
		exported = json.loads(json.dumps(export_annotations()))
		harness.open_fixture('sample', fresh=True)
		self.assertEqual(find_symbol('sum_two'), None)
		refresh = mock.Mock(wraps=compat.refresh_decompiler)
		with mock.patch.object(compat, 'refresh_decompiler', refresh):
			count = import_annotations(exported)
		self.assertEqual(refresh.call_count, 1)
		self.assertEqual(count, sum(len(section) for section in exported.values()))
		self.assertEqual(export_annotations(), exported)
		self.assertEqual(Func('sum_two').start, sym('sum_two'))
		self.assertEqual(Func('sum_two').comment, 'adds two numbers')
		self.assertEqual(list(Func('sum_two').arguments), ['left', 'right'])
		self.assertEqual(ptr(sym('compute') + 8).comment, 'third instruction')
		self.assertIn('player->level', Func('_player_power').pseudocode())
		self.assertIn('sum_two(', Func('_compute').pseudocode())

	def test_partial_and_bad_input(self):
		self.assertEqual(import_annotations({}), 0)
		self.assertEqual(import_annotations({ 'types' : ['struct Broken {'] }), 0)
		self.assertEqual(import_annotations({ 'names' : { str(sym('dispatch')) : 'by_decimal_key' } }), 1)
		self.assertEqual(Func(sym('by_decimal_key')).start, sym('by_decimal_key'))
		# A name another address has is not taken.
		self.assertEqual(import_annotations({ 'names' : { hex(sym('mul')) : 'by_decimal_key' } }), 0)
		# A function comment needs a function start.
		self.assertEqual(import_annotations({ 'function_comments' : { hex(sym('hero')) : 'not a function' } }), 0)
		self.assertEqual(import_annotations({ 'prototypes' : { hex(sym('greet')) : 'this is not C' } }), 0)
		with self.assertRaises(LookupError):
			import_annotations({ 'names' : { 'no_such_symbol' : 'x' } })

if __name__ == '__main__':
	harness.main()
