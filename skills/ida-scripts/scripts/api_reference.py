''' Write `references/api.md`: every public name of `ida_scripts` with its signature and the first line of its docstring.

`python skills/ida-scripts/scripts/api_reference.py` rewrites the file, `--check` only says whether it is current (exit code 1 when not). It reads the source with `ast`, so it needs no IDA and gives the same text on any Python.
'''

import ast
import os
import re
import sys

SKILL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE = os.path.join(os.path.dirname(os.path.dirname(SKILL)), 'ida_scripts')
TARGET = os.path.join(SKILL, 'references', 'api.md')

MODULES = ['session', 'memory', 'func', 'misc', 'struc', 'module', 'debugger', 'utils']
OPERATORS = { '__getitem__' : 'self[{0}]', '__setitem__' : 'self[{0}] = {1}', '__add__' : 'self + {0}', '__sub__' : 'self - {0}', '__call__' : 'self({0})' }

HEADER = '''# ida_scripts API

Generated from the source by `scripts/api_reference.py`. Do not edit it by hand.

Every public name, with its signature and the first line of its docstring. All of them come with `from ida_scripts import *`. `help(name)` in a session that has the library gives the whole docstring, parameters included.

In the signatures, `Address` stands for anything that means an address: an `int`, a symbol name or `'0x…'` string, a `Pointer`, and wherever it makes sense a `Func`. An entry without parentheses is a property or attribute, with its type after the colon, and `[rw]` marks one that can be assigned. Where the type is `Pointer`, `.addr` is the address as an `int`. Every class but `Pointer` also has `to_dict()`, its main properties as a JSON-friendly `dict`.

'''

def summary(node) -> str:
	''' First paragraph of a docstring, on one line. '''
	doc = ast.get_docstring(node) if not isinstance(node, str) else node
	return ' '.join((doc or '').strip().split('\n\n')[0].split())

def annotation(node) -> str:
	''' An annotation as short text: quotes and module prefixes gone, the address unions as `Address`. '''
	text = ast.unparse(node).replace("'", '').replace('"', '')
	text = re.sub(r'\b(ida_\w+|networkx)\.', '', text)
	text = re.sub(r'Union\[int, str, Pointer(, Func)?\]', 'Address', text)
	return re.sub(r'Optional\[(\w+)\]', r'\1 | None', text)

def signature(function: ast.FunctionDef, drop_self: bool) -> str:
	args = function.args
	positional = args.posonlyargs + args.args
	defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
	parts = []
	for arg, default in zip(positional, defaults):
		part = arg.arg + (f': {annotation(arg.annotation)}' if arg.annotation else '')
		parts.append(part + (f' = {ast.unparse(default)}' if default is not None else ''))
	if drop_self and parts:
		parts = parts[1:]
	if args.vararg:
		parts.append('*' + args.vararg.arg)
	if args.kwarg:
		parts.append('**' + args.kwarg.arg)
	returns = f' -> {annotation(function.returns)}' if function.returns else ''
	return f'({", ".join(parts)}){returns}'

def decorators(function: ast.FunctionDef) -> list:
	return [ast.unparse(d) for d in function.decorator_list]

def documented_attributes(body: list) -> list:
	''' `(name, docstring)` for each assignment that a string follows, the way pdoc documents variables. '''
	found = []
	for node, after in zip(body, body[1:]):
		if not (isinstance(after, ast.Expr) and isinstance(after.value, ast.Constant) and isinstance(after.value.value, str)):
			continue
		target = node.target if isinstance(node, ast.AnnAssign) else node.targets[0] if isinstance(node, ast.Assign) else None
		name = target.attr if isinstance(target, ast.Attribute) else target.id if isinstance(target, ast.Name) else None
		if name and not name.startswith('_'):
			kind = f': {annotation(node.annotation)}' if isinstance(node, ast.AnnAssign) else ''
			found.append((name + kind, summary(after.value.value)))
	return found

def class_lines(node: ast.ClassDef) -> list:
	functions = { n.name : n for n in node.body if isinstance(n, ast.FunctionDef) }
	init = functions.get('__init__')
	lines = [f'### {node.name}', '', f'`{node.name}{signature(init, True) if init else "()"}` {summary(node)}', '']
	setters = { d.split('.')[0] for f in functions.values() for d in decorators(f) if d.endswith('.setter') }
	attributes = documented_attributes(node.body) + (documented_attributes(init.body) if init else [])
	for name, text in attributes:
		lines.append(f'- `{name}` {text}')
	for item in node.body:
		if not isinstance(item, ast.FunctionDef):
			continue
		marks = decorators(item)
		if any(mark.endswith('.setter') for mark in marks):
			continue
		if item.name in OPERATORS:
			names = [arg.arg for arg in item.args.args[1:]]
			lines.append(f'- `{OPERATORS[item.name].format(*names)}` {summary(item)}'.rstrip())
		elif item.name.startswith('_'):
			continue
		elif 'property' in marks:
			kind = f': {annotation(item.returns)}' if item.returns else ''
			lines.append(f'- `{item.name}{kind}`{" [rw]" if item.name in setters else ""} {summary(item)}')
		elif 'staticmethod' in marks:
			lines.append(f'- `{node.name}.{item.name}{signature(item, False)}` {summary(item)}')
		else:
			lines.append(f'- `{item.name}{signature(item, True)}` {summary(item)}')
	return lines + ['']

def parse(name: str) -> ast.Module:
	with open(os.path.join(PACKAGE, name + '.py'), encoding='utf-8') as source:
		return ast.parse(source.read())

def module_lines(name: str) -> list:
	tree = parse(name)
	if name == 'utils':
		# utils has no __all__: what the package takes from it is what it offers.
		exported = next([alias.name for alias in n.names] for n in parse('__init__').body if isinstance(n, ast.ImportFrom) and n.module == 'utils')
		about = 'The errors the package raises, and helpers for showing results.'
	else:
		exported = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', '') == '__all__')
		about = summary(tree)
	defined = { n.name : n for n in tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef)) }
	aliases = [n for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Name)]
	defined.update({ n.targets[0].id : defined[n.value.id] for n in aliases if n.value.id in defined })
	variables = { text.split(':')[0] : (text, about) for text, about in documented_attributes(tree.body) }
	lines = [f'## {name}', '', about, '']
	if name == 'func':
		lines += ['`func(target: Address) -> Func` The module itself can be called: `func(\'main\')` is `Func(\'main\')`.', '']
	functions = []
	for public in exported:
		node = defined.get(public)
		if isinstance(node, ast.ClassDef):
			lines += class_lines(node)
		elif isinstance(node, ast.FunctionDef):
			functions.append(f'- `{public}{signature(node, False)}` {summary(node)}')
		elif public in variables:
			functions.append('- `{}` {}'.format(*variables[public]))
	if functions:
		lines += ['### Functions and values', ''] + functions + ['']
	return lines

def render() -> str:
	contents = ['Modules: ' + ', '.join(f'[{name}](#{name})' for name in MODULES) + '.', '']
	body = [line.rstrip() for name in MODULES for line in module_lines(name)]
	text = re.sub(r'\n{3,}', '\n\n', '\n'.join(contents + body))
	return HEADER + text.rstrip() + '\n'

def main() -> int:
	text = render()
	if sys.argv[1:] == ['--check']:
		with open(TARGET, encoding='utf-8') as current:
			if current.read() == text:
				return 0
		print(f'{os.path.relpath(TARGET)} is out of date: run python {os.path.relpath(__file__)}')
		return 1
	os.makedirs(os.path.dirname(TARGET), exist_ok=True)
	with open(TARGET, 'w', encoding='utf-8', newline='\n') as target:
		target.write(text)
	print(f'wrote {os.path.relpath(TARGET)}')
	return 0

if __name__ == '__main__':
	sys.exit(main())
