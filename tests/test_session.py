import os
import tempfile

import harness
from ida_scripts import compat
from ida_scripts.session import Database
from ida_scripts.utils import IDAError

class TestDatabase(harness.IDATestCase):

	def test_properties(self):
		db = self.database
		self.assertTrue(db.path.endswith('sample.i64'))
		self.assertEqual(db.filename, 'sample', f'input {db.input_path!r}, current {Database.current()!r}')
		self.assertTrue(db.input_path.endswith('sample'))
		self.assertEqual(db.image_base, 0x100000000)
		self.assertTrue(db.is_64bit)
		self.assertTrue(db.has_decompiler)
		self.assertGreaterEqual(db.func_count, 12)
		self.assertIn('sample', repr(db))

	def test_current_and_reopen_are_not_owned(self):
		for db in (Database.current(), Database.open(), Database.open(self.database.path), Database.open(self.database.input_path)):
			self.assertFalse(db.owned)
			self.assertEqual(db.path, self.database.path)
			db.close()
			self.assertIsNotNone(Database.current())

	def test_open_other_file_while_open(self):
		with self.assertRaises(IDAError):
			Database.open(__file__)

	def test_save_snapshot_keeps_the_open_file(self):
		before = self.database.path
		with tempfile.TemporaryDirectory() as folder:
			snapshot = os.path.join(folder, 'snapshot.i64')
			self.assertEqual(self.database.save(snapshot), snapshot)
			self.assertGreater(os.path.getsize(snapshot), 0)
		self.assertEqual(self.database.path, before)
		self.assertEqual(self.database.save(), before)

	def test_wait(self):
		self.database.wait()

class TestOpenClose(harness.IDATestCase):

	fresh = True

	def test_close_then_open_again(self):
		path = self.database.path
		self.assertTrue(self.database.owned)
		self.database.close()
		self.assertFalse(self.database.owned)
		self.assertIsNone(Database.current())
		with self.assertRaises(IDAError):
			Database.open()
		with self.assertRaises(IDAError):
			Database.open(path + '.missing')
		with Database.open(path) as db:
			self.assertTrue(db.owned)
			self.assertEqual(db.func_count, compat.func_count())
		self.assertIsNone(Database.current())

if __name__ == '__main__':
	harness.main()
