''' What makes the pseudocode of a function quick to read: a window of it, statements left out, and its calls with their arguments. '''

import json
import re
from unittest import mock

import harness
from harness import sym
from ida_scripts.func import Func, Call, hide_lines, code_part

class TestWindow(harness.IDATestCase):

	def test_start(self):
		cfunc = Func('_main').decompile()
		whole = cfunc.text().split('\n')
		self.assertEqual(cfunc.text(start=3).split('\n'), ['// … 3 lines above'] + whole[3:])
		self.assertEqual(cfunc.text(start=1).split('\n'), ['// … 1 line above'] + whole[1:])
		self.assertEqual(cfunc.text(start=3, max_lines=4).split('\n'), ['// … 3 lines above'] + whole[3:7] + [f'// … {len(whole) - 7} more lines'])
		self.assertEqual(cfunc.text(start=3, max_lines=len(whole)).split('\n'), ['// … 3 lines above'] + whole[3:])
		self.assertEqual(cfunc.text(start=len(whole) + 5), f'// … {len(whole)} lines above')
		self.assertEqual(cfunc.text(start=0), cfunc.text())
		with self.assertRaises(ValueError):
			cfunc.text(start=-1)

	def test_start_counts_what_is_shown(self):
		cfunc = Func('_compute').decompile()
		# The declarations are gone before the lines are counted.
		self.assertEqual(cfunc.text(start=2).split('\n')[1], '  v4 = add(a1, a2: 1);')
		self.assertEqual(cfunc.text(decls=True, start=2).split('\n')[1], cfunc.lines[2])
		self.assertEqual(cfunc.text(start=2, shorten=1).split('\n')[:2], ['// … 2 lines above', '  v… = a…(a…, a…: 1);'])

class TestHide(harness.IDATestCase):

	def test_hide(self):
		cfunc = Func('_main').decompile()
		whole = cfunc.text().split('\n')
		greet = '  greet(a1: *argv);'
		self.assertIn(greet, whole)
		self.assertEqual(cfunc.text(hide=r'greet\(').split('\n'), [line for line in whole if line != greet] + ['// … 1 line hidden'])
		self.assertEqual(cfunc.text(hide=[r'greet\(', r'^\s+return ']).split('\n'), [line for line in whole if line != greet and 'return' not in line] + ['// … 2 lines hidden'])
		self.assertEqual(cfunc.text(hide='no such text'), cfunc.text())
		self.assertEqual(cfunc.text(hide=[]), cfunc.text())
		with self.assertRaises(re.error):
			cfunc.text(hide='(')

	def test_hide_then_window(self):
		cfunc = Func('_main').decompile()
		rest = cfunc.text(hide=r'= v\d+ \+ ').split('\n')
		self.assertEqual(rest[-1], '// … 5 lines hidden')
		self.assertEqual(cfunc.text(hide=r'= v\d+ \+ ', start=2, max_lines=1).split('\n'), ['// … 2 lines above', rest[2], f'// … {len(rest) - 4} more lines', '// … 5 lines hidden'])

	def test_ignore(self):
		cfunc = Func('_main').decompile()
		whole = cfunc.text().split('\n')
		self.assertEqual(cfunc._ignored_names(), set())
		self.assertEqual(cfunc.text(ignore=True), cfunc.text())
		with mock.patch.object(Func, 'ignore', { '^_greet$', '^_compute$' }):
			# The pseudocode spells both without their underscore.
			self.assertEqual(cfunc._ignored_names(), { 'greet', 'compute' })
			text = cfunc.text(ignore=True).split('\n')
			self.assertEqual(text, [line for line in whole if 'greet(' not in line] + ['// … 1 line hidden'])
			# The result of compute is used, so its call stays.
			self.assertTrue(any('compute(' in line for line in text))
			self.assertEqual(cfunc.text().split('\n'), whole)
		with mock.patch.object(Func, 'ignore', { '^_printf$' }):
			# greet returns what printf returns.
			greet = Func('_greet').decompile()
			self.assertEqual(greet._ignored_names(), { 'printf' })
			self.assertEqual(greet.text(ignore=True), greet.text())
		with mock.patch.object(Func, 'ignore', { 'no_such_function' }):
			self.assertEqual(cfunc.text(ignore=True), cfunc.text())

	def test_through_func(self):
		f = Func('_main')
		with mock.patch.object(Func, 'ignore', { '^_greet$' }):
			self.assertEqual(f.pseudocode(ignore=True, start=2, max_lines=3), f.decompile().text(ignore=True, start=2, max_lines=3))
			self.assertNotIn('greet(', f.pseudocode(ignore=True))

class TestHideLines(harness.IDATestCase):
	''' The text work behind `hide` and `ignore`, on pseudocode as IDA writes it for a runtime that guards and checks everywhere. '''

	NAMES = { 'init_once', 'throw_null', 'class_init' }

	def hide(self, text: str, *patterns: str):
		lines, hidden = hide_lines(text.split('\n'), [re.compile(pattern) for pattern in patterns], self.NAMES)
		return '\n'.join(lines), hidden

	def test_code_part(self):
		self.assertEqual(code_part('  v1 = 2; // x0'), '  v1 = 2;')
		self.assertEqual(code_part('  puts("a // b");  '), '  puts("a // b");')
		self.assertEqual(code_part('// only a comment'), '')
		self.assertEqual(code_part('  if ( a )'), '  if ( a )')

	def test_nothing_to_hide(self):
		text = 'int f()\n{\n  return g();\n}'
		self.assertEqual(self.hide(text), (text, 0))
		self.assertEqual(hide_lines(text.split('\n'), [], set()), (text.split('\n'), 0))

	def test_a_statement_among_others(self):
		self.assertEqual(self.hide('{\n  a = 1;\n  init_once(a1: &x);\n  b = 2;\n}'), ('{\n  a = 1;\n  b = 2;\n}', 1))
		self.assertEqual(self.hide('{\nLABEL_3:\n  throw_null(a1: 0); // never returns\n  b = 2;\n}'), ('{\nLABEL_3:\n  b = 2;\n}', 1))
		self.assertEqual(self.hide('  switch ( q )\n  {\n    case 1:\n      class_init(a1: T);\n      break;\n  }'), ('  switch ( q )\n  {\n    case 1:\n      break;\n  }', 1))

	def test_a_used_result_stays(self):
		for text in ('  v9 = init_once(a1: T);', '  return throw_null(a1: 0);', '  if ( class_init(a1: T) )\n    a = 1;', '  other(a1: init_once);', '  init_once_more(a1: 1);'):
			self.assertEqual(self.hide(text), (text, 0), text)

	def test_a_wrapped_call(self):
		self.assertEqual(self.hide('  a = 1;\n  init_once(\n    a1: &x,\n    a2: 3);\n  b = 2;'), ('  a = 1;\n  b = 2;', 3))
		# Without its end in sight it stays.
		text = '  init_once(\n    a1: &x,\n  b = 2;'
		self.assertEqual(self.hide(text), (text, 0))

	def test_an_emptied_block_goes_with_its_if(self):
		text = '  if ( (flag & 1) == 0 )\n  {\n    init_once(a1: &A);\n    init_once(a1: &B);\n    flag = 1;\n  }\n  v2 = 1;'
		# The flag is still set in there.
		self.assertEqual(self.hide(text), ('  if ( (flag & 1) == 0 )\n  {\n    flag = 1;\n  }\n  v2 = 1;', 2))
		self.assertEqual(self.hide(text, r'flag = 1;'), ('  v2 = 1;', 6))

	def test_blocks_empty_from_the_inside_out(self):
		text = '  if ( a )\n  {\n    if ( b )\n    {\n      throw_null(a1: 0);\n    }\n  }\n  c = 1;'
		self.assertEqual(self.hide(text), ('  c = 1;', 7))
		text = '  if ( a )\n  {\n    if ( b )\n    {\n      throw_null(a1: 0);\n    }\n    d = 1;\n  }'
		self.assertEqual(self.hide(text), ('  if ( a )\n  {\n    d = 1;\n  }', 4))

	def test_a_block_that_was_empty_stays(self):
		text = '  if ( a )\n  {\n  }\n  b = 1;'
		self.assertEqual(self.hide(text), (text, 0))

	def test_an_if_without_braces_goes_with_its_body(self):
		self.assertEqual(self.hide('  v2 = p;\n  if ( !v2 )\n    throw_null(a1: 0);\n  v3 = 1;'), ('  v2 = p;\n  v3 = 1;', 2))
		self.assertEqual(self.hide('  if ( !*(_DWORD *)(T + 228)\n    && x )\n    class_init(a1: T);\n  v3 = 1;'), ('  v3 = 1;', 3))
		self.assertEqual(self.hide('  if ( o )\n    if ( p )\n      throw_null(a1: p);\n  v3 = 1;'), ('  v3 = 1;', 3))

	def test_an_else_decides(self):
		# The first branch cannot go while the else is there.
		text = '  if ( x )\n    throw_null(a1: v2);\n  else\n    v3 = 1;'
		self.assertEqual(self.hide(text), (text, 0))
		self.assertEqual(self.hide('  if ( y )\n    v3 = 2;\n  else\n    throw_null(a1: v2);\n  v4 = 1;'), ('  if ( y )\n    v3 = 2;\n  v4 = 1;', 2))
		self.assertEqual(self.hide('  if ( a )\n    x = 1;\n  else if ( b )\n    throw_null(a1: 0);\n  z = 1;'), ('  if ( a )\n    x = 1;\n  z = 1;', 2))
		text = '  if ( a )\n    x = 1;\n  else if ( b )\n    throw_null(a1: 0);\n  else\n    z = 1;'
		self.assertEqual(self.hide(text), (text, 0))
		# A block that lost its lines stays as an empty one in front of an else.
		self.assertEqual(self.hide('  if ( w )\n  {\n    throw_null(a1: w);\n  }\n  else\n  {\n    keep();\n  }'), ('  if ( w )\n  {\n  }\n  else\n  {\n    keep();\n  }', 1))
		self.assertEqual(self.hide('  if ( w )\n  {\n    keep();\n  }\n  else\n  {\n    throw_null(a1: w);\n  }\n  z = 1;'), ('  if ( w )\n  {\n    keep();\n  }\n  z = 1;', 4))

	def test_a_loop_keeps_its_body(self):
		for text in ('  while ( z )\n    throw_null(a1: z);', '  for ( i = 0; i < 3; ++i )\n    init_once(a1: i);', '  do\n    class_init(a1: T);\n  while ( z );', '  while ( z )\n  {\n    throw_null(a1: z);\n  }'):
			lines, hidden = self.hide(text)
			self.assertTrue(lines.startswith(text.split('\n')[0]), text)
			self.assertLessEqual(hidden, 1, text)
		text = '  while ( z )\n    throw_null(a1: z);'
		self.assertEqual(self.hide(text), (text, 0))
		# Inside the braces of a loop a statement can go, the loop stays.
		self.assertEqual(self.hide('  while ( z )\n  {\n    throw_null(a1: z);\n  }'), ('  while ( z )\n  {\n  }', 1))

	def test_a_pattern_is_a_statement_too(self):
		self.assertEqual(self.hide('  if ( a )\n    flag = 1;\n  b = 2;', r'flag = 1;'), ('  b = 2;', 2))
		text = '  if ( a )\n    flag = 1;\n  else\n    b = 2;'
		self.assertEqual(self.hide(text, r'flag = 1;'), (text, 0))

class TestDecompiledCalls(harness.IDATestCase):

	def test_arguments(self):
		calls = Func('_compute').decompile().calls
		self.assertEqual([(call.kind, call.text, call.args) for call in calls], [('direct', '_add', ['a1', '1']), ('direct', '_mul', ['v4', '2']), ('direct', '_leaf', []), ('direct', '_add', ['v3', 'v1'])])
		self.assertEqual([call.target for call in calls], [Func('_add'), Func('_mul'), Func('_leaf'), Func('_add')])
		# The same calls, at the same instructions, as the disassembly has.
		self.assertEqual([(call.site, call.text) for call in calls], [(call.site, call.text) for call in Func('_compute').calls])

	def test_indirect(self):
		calls = Func('_apply').decompile().calls
		self.assertEqual([(call.kind, call.target, call.text, call.args) for call in calls], [('indirect', None, 'a1', ['a2', 'a3'])])
		self.assertEqual(calls[0].site, Func('_apply').calls[0].site)

	def test_arguments_as_the_pseudocode_has_them(self):
		call = Func('_greet').decompile().calls[0]
		self.assertEqual((call.text, call.args), ('_printf', ['"hello fixture %s\\n"', 'a1']))
		by_name = { call.text : call.args for call in Func('_main').decompile().calls }
		self.assertEqual(by_name['_apply'], ['_add', '3', '4'])
		self.assertEqual(by_name['_player_power'], ['&_hero'])
		self.assertEqual(by_name['_uses_strings'], [])
		self.assertEqual(len(by_name), 8)

	def test_ignore(self):
		with mock.patch.object(Func, 'ignore', { '^_mul$', 'lea' }):
			self.assertEqual([call.text for call in Func('_compute').decompile().calls], ['_add', '_add'])
			# An indirect call has no name to ignore.
			self.assertEqual(len(Func('_apply').decompile().calls), 1)
		with mock.patch.object(Func, 'ignore', { 'a1' }):
			self.assertEqual(len(Func('_apply').decompile().calls), 1)

	def test_json_and_repr(self):
		call = Func('_compute').decompile().calls[0]
		plain = Func('_compute').calls[0]
		self.assertEqual(json.loads(json.dumps(call.to_dict())), { 'site' : hex(call.site), 'kind' : 'direct', 'target' : hex(sym('add')), 'text' : '_add', 'args' : ['a1', '1'] })
		self.assertEqual(repr(call), f"<Call site={hex(call.site)}, kind=direct, target={hex(sym('add'))}, text=_add, args=['a1', '1']>")
		self.assertEqual(repr(plain), f"<Call site={hex(call.site)}, kind=direct, target={hex(sym('add'))}, text=_add>")
		self.assertIsNone(plain.args)
		self.assertNotIn('args', plain.to_dict())
		self.assertNotEqual(call, plain)
		self.assertEqual(call, Func('_compute').decompile().calls[0])
		self.assertEqual(Call(1, 'direct', None, 'x', []).to_dict()['args'], [])

if __name__ == '__main__':
	harness.main()
