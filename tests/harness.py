''' Shared base for the tests that need a database.

Each test process opens its own temporary copy of a fixture database, so test files can run side by side and may change the database freely.
'''

import atexit
import os
import shutil
import sys
import tempfile
import unittest
import warnings

TESTS = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(TESTS, '.cache')
sys.path.insert(0, os.path.dirname(TESTS))

opened = None
dirty = False

def open_fixture(name: str, fresh: bool = False):
	''' Open a temporary copy of a fixture database.

	The copy already open is reused, unless `fresh` is set or the previous user asked for a fresh one (and so may have changed it).
	'''
	global opened, dirty
	from ida_scripts.session import Database
	if opened and opened[0] == name and not fresh and not dirty:
		return opened[1]
	close_fixture()
	dirty = fresh
	folder = tempfile.mkdtemp(prefix='ida_scripts_test_')
	path = os.path.join(folder, name + '.i64')
	shutil.copy(os.path.join(CACHE, name + '.i64'), path)
	database = Database.open(path)
	# Only from here on: the filter set before idalib starts makes it crash on its own deprecated calls.
	warnings.simplefilter('error', DeprecationWarning)
	opened = (name, database, folder)
	return database

def close_fixture():
	''' Close the open fixture database and remove its temporary copy. '''
	global opened
	if opened:
		opened[1].close()
		shutil.rmtree(opened[2], ignore_errors=True)
		opened = None

atexit.register(close_fixture)

class IDATestCase(unittest.TestCase):
	''' A test case with a fixture database open.

	Set `fixture` to the fixture's name. Set `fresh` in a class that changes the database: it then starts from an unchanged copy, and so does the class after it.
	'''

	fixture = 'sample'
	fresh = False

	@classmethod
	def setUpClass(cls):
		cls.database = open_fixture(cls.fixture, cls.fresh)

def sym(name: str) -> int:
	''' Address of a symbol of the open fixture, by its C name. '''
	import ida_idaapi
	import ida_name
	for candidate in ('_' + name, name):
		ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
		if ea != ida_idaapi.BADADDR:
			return ea
	raise LookupError(name)

def analyze(binary: str):
	''' Make the analysed database of a fixture binary. '''
	from ida_scripts.session import Database
	database = Database.open(binary, analyze=True)
	database.close(save=True)

def main():
	''' Run the tests of the calling file. '''
	unittest.main(module='__main__', verbosity=1)

if __name__ == '__main__':
	if len(sys.argv) == 3 and sys.argv[1] == '--analyze':
		analyze(sys.argv[2])
