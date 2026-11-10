''' Provides class(es) for opening, saving and closing the database, so the same script runs headless and inside IDA. '''

import os
from typing import *

from . import compat
from .compat import IN_IDA
from .utils import *

if IN_IDA:
	import ida_auto
	import ida_loader
	import ida_nalt

__all__ = ['Database']

def same_file(a: str, b: str) -> bool:
	return bool(a) and bool(b) and os.path.realpath(a) == os.path.realpath(b)

@auto_repr(['filename', 'path'])
class Database:
	''' Represent the open database.

	Get one with `Database.open` or `Database.current`. Only one database can be open in a process.

	A `Database` is also a context manager, closing the database on exit when `Database.open` was what opened it:

	```
	with Database.open('target.i64') as db:
		print(db.func_count)
	```
	'''

	@staticmethod
	def current() -> Optional['Database']:
		''' The database that is open now, `None` when there is none. '''
		return Database(False) if ida_loader.get_path(ida_loader.PATH_TYPE_IDB) else None

	@staticmethod
	def open(path: str = None, analyze: bool = False) -> 'Database':
		''' Open a binary or an existing database.

		When a database is already open (inside IDA, or in a worker that opened it for you) and `path` is `None` or names that same file, this returns the open one and `Database.close` leaves it alone.

		Parameters
		----------
		path : str, default = None
			A binary, or an `.i64`. `None` means the database that is already open.
		analyze : bool, default = False
			Run auto-analysis and wait for it. Wanted for a binary that has no database yet.

		Returns
		-------
		`Database`

		Raises
		------
		IDAError
			When the file cannot be opened, or another database is open.
		'''
		opened = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
		if opened:
			inputs = (opened, ida_nalt.get_input_file_path(), os.path.splitext(opened)[0])
			if path is None or any(same_file(path, candidate) for candidate in inputs):
				return Database(False)
			raise IDAError(f'{opened} is open, close it before opening {path}')
		if path is None:
			raise IDAError('no database is open, give a path')
		if not compat.IDALIB:
			raise IDAError('a database can only be opened from Python that hosts IDA as a library (idalib)')
		if not os.path.exists(path):
			raise IDAError(f'{path} does not exist')
		import idapro
		code = idapro.open_database(path, analyze)
		if code != 0:
			raise IDAError(f'cannot open {path} (idalib error {code})')
		ida_auto.auto_wait()
		return Database(True)

	def __init__(self, owned: bool):
		''' Init a handle to the open database. `owned` says whether closing it is ours to do. '''
		self.owned = owned
		''' Whether `Database.open` opened this database, so `Database.close` closes it. '''

	@property
	def path(self) -> str:
		''' Path of the database file. '''
		return ida_loader.get_path(ida_loader.PATH_TYPE_IDB)

	@property
	def input_path(self) -> str:
		''' Path of the file the database was made from. '''
		return ida_nalt.get_input_file_path()

	@property
	def filename(self) -> str:
		''' Name of the file the database was made from. '''
		return ida_nalt.get_root_filename()

	@property
	def image_base(self) -> int:
		''' Image base. '''
		return compat.image_base()

	@property
	def is_64bit(self) -> bool:
		''' Whether the database is 64-bit. '''
		return compat.is_64bit()

	@property
	def has_decompiler(self) -> bool:
		''' Whether the Hex-Rays decompiler is available for this database. '''
		return compat.has_decompiler()

	@property
	def func_count(self) -> int:
		''' Number of functions. '''
		return compat.func_count()

	def wait(self):
		''' Wait for auto-analysis to finish. '''
		ida_auto.auto_wait()

	def save(self, path: str = None) -> str:
		''' Save the database.

		Parameters
		----------
		path : str, default = None
			Where to write a snapshot. The open database stays the same file. `None` saves in place.

		Returns
		-------
		str
			The path written.
		'''
		if not ida_loader.save_database(path, 0):
			raise IDAError(f'cannot save the database to {path or self.path}')
		return path or self.path

	def close(self, save: bool = False):
		''' Close the database, when `Database.open` opened it. Does nothing otherwise. '''
		if not self.owned:
			return
		import idapro
		idapro.close_database(save)
		self.owned = False

	def __enter__(self) -> 'Database':
		return self

	def __exit__(self, *exc):
		self.close()
