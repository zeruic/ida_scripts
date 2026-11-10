''' A minimal stand-in for `networkx`, with only what `ida_scripts.func` uses. The real package is not installed here.

Tests put this folder on `sys.path` only while they import it. Like `networkx`, a node added again under an equal key keeps the first key object.
'''

from typing import *

class DiGraph:
	''' A directed graph whose successors and predecessors keep insertion order. '''

	def __init__(self):
		self.graph = {}
		''' Attributes of the graph itself. '''
		self._keys = {}
		self._succ = {}
		self._pred = {}
		self._attributes = {}

	def add_node(self, node: Hashable, **attributes):
		''' Add a node, or update the attributes of the node equal to it. '''
		if node not in self._keys:
			self._keys[node] = node
			self._succ[node] = {}
			self._pred[node] = {}
			self._attributes[node] = {}
		self._attributes[self._keys[node]].update(attributes)

	def add_edge(self, u: Hashable, v: Hashable):
		''' Add an edge, and its ends when they are new. '''
		self.add_node(u)
		self.add_node(v)
		u, v = self._keys[u], self._keys[v]
		self._succ[u][v] = {}
		self._pred[v][u] = {}

	def successors(self, node: Hashable) -> Iterator[Hashable]:
		''' The nodes this one has an edge to. '''
		if node not in self._succ:
			raise KeyError(f'the node {node} is not in the graph')
		return iter(self._succ[node])

	def predecessors(self, node: Hashable) -> Iterator[Hashable]:
		''' The nodes that have an edge to this one. '''
		if node not in self._pred:
			raise KeyError(f'the node {node} is not in the graph')
		return iter(self._pred[node])

	@property
	def nodes(self) -> Dict[Hashable, dict]:
		''' Every node, with its attributes. '''
		return self._attributes

	def __len__(self) -> int:
		return len(self._succ)

	def __iter__(self) -> Iterator[Hashable]:
		return iter(self._succ)

	def __contains__(self, node: Hashable) -> bool:
		return node in self._succ

def dfs_preorder_nodes(graph: DiGraph, source: Hashable) -> Iterator[Hashable]:
	''' The nodes reachable from `source`, depth first, each before its successors. '''
	seen = set()
	stack = [graph._keys[source]]
	while stack:
		node = stack.pop()
		if node in seen:
			continue
		seen.add(node)
		yield node
		stack.extend(reversed([child for child in graph.successors(node) if child not in seen]))

def topological_sort(graph: DiGraph) -> Iterator[Hashable]:
	''' Every node, each before its successors. Raises `ValueError` on a cycle. '''
	indegree = { node : len(graph._pred[node]) for node in graph }
	ready = [node for node, degree in indegree.items() if degree == 0]
	count = 0
	while ready:
		node = ready.pop(0)
		count += 1
		yield node
		for child in graph.successors(node):
			indegree[child] -= 1
			if indegree[child] == 0:
				ready.append(child)
	if count != len(graph):
		raise ValueError('the graph has a cycle')
