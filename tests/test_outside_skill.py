''' The skill in `skills/ida-scripts` says what the package does: its API reference is current, and its examples use names that exist. '''

import ast
import builtins
import importlib.util
import inspect
import os
import re
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import ida_scripts
from ida_scripts import compat

SKILL = os.path.join(REPO, 'skills', 'ida-scripts')
PAGES = ['SKILL.md', os.path.join('references', 'debugging.md')]
ROOTS = { name : getattr(ida_scripts, name) for name in ida_scripts.__all__ }
ROOTS['compat'] = compat

def has(root: str, attribute: str) -> bool:
	''' Whether `root.attribute` exists, without reading a property of an instance such as `dbg`, which would ask IDA. '''
	item = ROOTS[root]
	if inspect.ismodule(item):
		return hasattr(item, attribute)
	if inspect.isclass(item):
		return hasattr(item, attribute) or bool(re.search(rf'self\.{attribute}\b\s*[:=]', inspect.getsource(item.__init__)))
	return hasattr(type(item), attribute) or attribute in vars(item)

def page(name: str) -> str:
	with open(os.path.join(SKILL, name), encoding='utf-8') as file:
		return file.read()

def code_blocks(text: str) -> list:
	return re.findall(r'```python\n(.*?)```', text, re.S)

def assigned(tree: ast.AST) -> set:
	''' Every name the code binds itself: assignments, loop and lambda variables, definitions and imports. '''
	names = set()
	for node in ast.walk(tree):
		if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
			names.add(node.id)
		elif isinstance(node, ast.arg):
			names.add(node.arg)
		elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
			names.add(node.name)
		elif isinstance(node, (ast.Import, ast.ImportFrom)):
			names.update((alias.asname or alias.name).split('.')[0] for alias in node.names)
	return names

class TestSkill(unittest.TestCase):

	def test_api_reference_is_current(self):
		spec = importlib.util.spec_from_file_location('api_reference', os.path.join(SKILL, 'scripts', 'api_reference.py'))
		generator = importlib.util.module_from_spec(spec)
		spec.loader.exec_module(generator)
		self.assertEqual(page(os.path.join('references', 'api.md')), generator.render(), 'run python skills/ida-scripts/scripts/api_reference.py')

	def test_reference_has_every_public_name(self):
		text = page(os.path.join('references', 'api.md'))
		for name in ida_scripts.__all__:
			if not inspect.ismodule(ROOTS[name]):
				self.assertTrue(re.search(rf'(`|### ){name}\b', text), f'api.md has {name}')

	def test_examples_parse_and_call_what_exists(self):
		for name in PAGES:
			blocks = [ast.parse(block) for block in code_blocks(page(name))]
			self.assertTrue(blocks, f'{name} has examples')
			known = set(ROOTS) | set(dir(builtins)) | { 'REPO' }
			for tree in blocks:
				known |= assigned(tree)
			for tree in blocks:
				for node in ast.walk(tree):
					if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
						self.assertIn(node.func.id, known, f'{name} calls {node.func.id}()')
					if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in ROOTS:
						self.assertTrue(has(node.value.id, node.attr), f'{name} uses {node.value.id}.{node.attr}')
					if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in ROOTS:
						target = getattr(ROOTS[node.func.value.id], node.func.attr, None) if has(node.func.value.id, node.func.attr) else None
						if not callable(target):
							continue
						parameters = inspect.signature(target).parameters
						if any(p.kind == p.VAR_KEYWORD for p in parameters.values()):
							continue
						for keyword in node.keywords:
							self.assertIn(keyword.arg, parameters, f'{name} passes {keyword.arg}= to {node.func.value.id}.{node.func.attr}')

	def test_names_in_the_text_exist(self):
		classes = '|'.join(name for name, item in ROOTS.items() if inspect.isclass(item) or name in ('dbg', 'compat'))
		for name in PAGES:
			for root, attribute in re.findall(rf'`(?:[^`]*?[^\w`.])?({classes})\.(\w+)', page(name)):
				self.assertTrue(has(root, attribute), f'{name} mentions {root}.{attribute}')

if __name__ == '__main__':
	unittest.main()
