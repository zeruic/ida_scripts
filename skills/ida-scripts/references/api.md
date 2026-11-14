# ida_scripts API

Generated from the source by `scripts/api_reference.py`. Do not edit it by hand.

Every public name, with its signature and the first line of its docstring. All of them come with `from ida_scripts import *`. `help(name)` in a session that has the library gives the whole docstring, parameters included.

In the signatures, `Address` stands for anything that means an address: an `int`, a symbol name or `'0x…'` string, a `Pointer`, and wherever it makes sense a `Func`. An entry without parentheses is a property or attribute, with its type after the colon, and `[rw]` marks one that can be assigned. Where the type is `Pointer`, `.addr` is the address as an `int`. Every class but `Pointer` also has `to_dict()`, its main properties as a JSON-friendly `dict`.

Modules: [session](#session), [memory](#memory), [func](#func), [misc](#misc), [struc](#struc), [module](#module), [debugger](#debugger), [utils](#utils).

## session

Provides class(es) for opening, saving and closing the database, so the same script runs headless and inside IDA.

### Database

`Database(owned: bool)` Represent the open database.

- `owned` Whether `Database.open` opened this database, so `Database.close` closes it.
- `Database.current() -> Database | None` The database that is open now, `None` when there is none.
- `Database.open(path: str = None, analyze: bool = False) -> Database` Open a binary or an existing database.
- `path: str` Path of the database file.
- `input_path: str` Path of the file the database was made from.
- `filename: str` Name of the file the database was made from.
- `image_base: int` Image base.
- `is_64bit: bool` Whether the database is 64-bit.
- `has_decompiler: bool` Whether the Hex-Rays decompiler is available for this database.
- `func_count: int` Number of functions.
- `wait()` Wait for auto-analysis to finish.
- `save(path: str = None) -> str` Save the database.
- `close(save: bool = False)` Close the database, when `Database.open` opened it. Does nothing otherwise.

## memory

Provides class(es) for reading and writing memory, of the database or of the debugged process, and for looking at the code around an address.

### Pointer

`Pointer(addr: Address)` Represent an address. The `Pointer` class offers convenient access to read/write from a memory address.

- `default_string_encoding: str` The default string encoding used by `Pointer.string`. Defaults to `'utf-8'`.
- `addr: int` The address.
- `read(size: int, offset: int = 0) -> bytes` Read bytes from `self.addr + offset` of given size.
- `write(bytes: bytes, offset: int = 0, verify: bool = False) -> bool` Write bytes to `self.addr + offset` in the debugged process.
- `swap(data: bytes, offset: int = 0) -> bytes` Write `data` to the debugged process and return the bytes it replaced.
- `u8(value: int = None) -> Union[int, bool]` Read/Write uint8.
- `u16(value: int = None) -> Union[int, bool]` Read/Write uint16.
- `u32(value: int = None) -> Union[int, bool]` Read/Write uint32.
- `u64(value: int = None) -> Union[int, bool]` Read/Write uint64.
- `s8(value: int = None) -> Union[int, bool]` Read/Write int8.
- `s16(value: int = None) -> Union[int, bool]` Read/Write int16.
- `s32(value: int = None) -> Union[int, bool]` Read/Write int32.
- `s64(value: int = None) -> Union[int, bool]` Read/Write int64.
- `f32(value: float = None) -> Union[float, bool]` Read/Write a 32-bit float.
- `f64(value: float = None) -> Union[float, bool]` Read/Write a 64-bit float.
- `array(format: str, count: int) -> List[Union[int, float]]` Read `count` consecutive values.
- `read_terminated(width: int = 1) -> bytes` Read up to a terminator of `width` zero bytes, the terminator not included. Stops after `STR_MAXLEN` bytes.
- `string(value: str = None, encoding: str = None, read_length: int = None) -> Union[str, bool]` Read/Write string, optionally specifying a custom encoding and length to read.
- `wstring(value: str = None, read_length: int = None) -> Union[str, bool]` Read/Write a UTF-16 string.
- `ptr(value: Union[Pointer, int] = None) -> Union[Pointer, bool]` Read/Write pointer.
- `hexdump_str(len: int = 100, offset: int = 0) -> str` Generate hexdump from `self.addr + offset` of specified length.
- `hexdump(len: int = 100, offset: int = 0)` Print hexdump from `self.addr + offset` of specified length.
- `name: str` [rw] The name at this address, `''` when it has none. Assign to rename.
- `rename(name: str, force: bool = False) -> bool` Name this address.
- `comment: str` [rw] The comment at this address, the repeatable one when there is no regular one. Assign to set a regular comment.
- `set_comment(text: str, repeatable: bool = False) -> bool` Set the regular or the repeatable comment at this address.
- `segment: str` Name of the segment containing this address, `''` when it is in none.
- `rva: int` Offset of this address from the database's image base.
- `is_code: bool` Whether this address is the start of an instruction.
- `func: Func | None` The function containing this address, `None` when it is in no function.
- `module: Module | None` The module of the debugged process containing this address, `None` when there is none.
- `xrefs_to() -> List[Xref]` References to this address, ordinary flow from the previous instruction left out.
- `xrefs_from() -> List[Xref]` References from this address, ordinary flow to the next instruction left out.
- `disasm(count: int = 1, before: int = 0) -> List[Insn]` Decode `count` consecutive instructions starting here, after up to `before` instructions that lead up to this address. Stops early at the first undecodable one.
- `self + other`
- `self - other`
- `add(other: Union[Pointer, int]) -> Pointer` `self + other`.
- `sub(other: Union[Pointer, int]) -> Pointer` `self - other`.

### Xref

`Xref(frm: int, to: int, type: int)` Represent one reference between two addresses.

- `frm: Pointer` Where the reference comes from.
- `to: Pointer` Where it points.
- `type: int` IDA's reference type.
- `kind: str` What the reference does: `'call'`, `'jump'`, `'read'`, `'write'`, `'offset'` or `'other'`.
- `is_code: bool` Whether the reference comes from an instruction, as opposed to data such as a pointer table.
- `func: Func | None` The function containing the origin, `None` when it comes from outside any function.

### Insn

`Insn(address: Address)` Represent one instruction.

- `address: int` Instruction address.
- `defined: bool` Whether the database defines this address as code.
- `size: int` Instruction size in bytes.
- `is_call: bool` Whether this is a call instruction.
- `mnem: str` Mnemonic.
- `ops: List[str]` Operands as text.
- `text: str` The disassembly line.
- `target: Pointer | None` Where a direct call or jump goes, `None` for anything else.
- `call_target: Func | None` The function a direct call goes to, `None` for anything else.
- `to_dict() -> Dict[str, Any]` The instruction as a JSON-friendly `dict`.

### Functions and values

- `ptr(addr: Address) -> Pointer` Initialise a `Pointer`.
- `disasm(start: Address, end: Address) -> List[Insn]` Every instruction in `[start, end)`, whether or not the range belongs to a function.

## func

Provides class(es) for interacting with functions.

`func(target: Address) -> Func` The module itself can be called: `func('main')` is `Func('main')`.

### Func

`Func(target: Address)` Represent a function.

- `ignore: Set[str]` Regular expressions of callee names that `Func.callees` and `Func.calls` leave out, such as runtime helpers that drown the list. Searched for anywhere in the name (`re.search`). Empty by default.
- `start: int` Function start address.
- `Func.find(name: str) -> Func | None` Find function by name, `None` when there is none. A name that is not there is tried with a leading underscore, so `main` finds a Mach-O file's `_main`.
- `Func.at(addr: Address) -> Func | None` The function containing an address, `None` when it is in no function.
- `Func.search(pattern: str, limit: int = None) -> List[Func]` The functions whose name matches a regular expression, in address order.
- `Func.all() -> Iterator[Func]` Every function, in address order.
- `name: str` [rw] Function name. Assign to rename.
- `rename(name: str, force: bool = False) -> bool` Rename the function. With `force`, IDA may use a numbered variant when the name is taken.
- `end: int` End address of the function's first chunk.
- `size: int` Function size in bytes, all chunks together.
- `chunks: List[Tuple[int, int]]` Every chunk of the function as `(start, end)`, in address order. More than one when the function has tails.
- `contains(addr: Address) -> bool` Whether an address lies in any chunk of this function.
- `tif: tinfo_t | None` Type of the function, `None` when it has none.
- `arguments: Dict[str, tinfo_t]` Return a `dict` of argument name to type info.
- `comment: str` [rw] The function comment, repeated wherever the function is referenced. `''` when there is none. Assign to set it.
- `prototype: str` [rw] The function's C prototype, `''` when it has no type. Assign a C declaration to set it.
- `set_prototype(declaration: str) -> bool` Apply a C prototype such as `int __fastcall add(int a, int b)`. Returns whether IDA accepted it.
- `decompile() -> CFunc` Decompile this function. Raises `DecompileError` when the decompiler fails.
- `pseudocode(**options) -> str` The decompiled function as text: `decompile().text(**options)`, see `CFunc.text` for the options. Raises `DecompileError` when the decompiler fails.
- `disasm() -> str` The function's disassembly, one instruction per line after its address, every chunk in address order with a blank line between chunks.
- `call(*args) -> Any` Call this function in the debugged process with its prototype, through `Debugger.call`, and return its result.
- `is_thunk: bool` Whether this function only jumps to another one: IDA marks it as a thunk, as it does an import stub, or it is a single jump to the start of another function.
- `thunk_target: Func | None` The function a thunk jumps to. `None` when this is not a thunk, or when the target is in no function of the database, as for an import.
- `insns: List[Insn]` Every instruction, all chunks in address order.
- `fingerprint: str` SHA-256 (hex) of the sequence of mnemonics, all chunks in address order. It does not depend on addresses, so the same code has the same fingerprint in another build.
- `calls: List[Call]` The calls this function makes, in address order. Calls to a name that matches `Func.ignore` are left out.
- `callees: List[Func]` The functions this one calls, directly or as a tail call, without duplicates and sorted by address. Names that match `Func.ignore` are left out.
- `callers: List[Func]` The functions that call this one, directly or as a tail call, without duplicates and sorted by address.
- `xrefs_to: List[Xref]` The references to the function's start, ordinary flow left out.
- `data_refs: List[Pointer]` The addresses the function refers to as data, without duplicates and sorted: the globals it reads and writes, and the addresses it takes, such as a string's or a function's.
- `strings: List[Tuple[Pointer, str]]` The string literals the function refers to, as `(address, text)` sorted by address. Only strings that the database defines count.
- `outline(width: int = 120, max_lines: int = 200) -> str` What the function does at a glance: the calls it makes, in order, and the texts it refers to.

### CFunc

`CFunc(original: Func, decompiled: cfunc_t)` Represent a decompiled function.

- `original` The `Func` object from which this object is derived.
- `decompiled` The decompiled `ida_hexrays.cfunc_t` object.
- `body: DiGraph` The graph representing the decompiled function, each node a `CItem`. Built on first use, needs `networkx`.
- `body_root: CItem` The root node of the graph for this function.
- `lines: List[str]` The pseudocode, one string per line.
- `pseudocode: str` Pseudocode of the decompiled function.
- `calls: List[Call]` The calls in the pseudocode with their arguments, in address order. Calls to a name that matches `Func.ignore` are left out.
- `text(decls: bool = False, max_lines: int = None, shorten: int = None, start: int = 0, hide: Union[str, Iterable[str]] = None, ignore: bool = False) -> str` The pseudocode, without the declarations of its local variables. The options cut it to a window (`start`, `max_lines`), shorten long identifiers (`shorten`), and leave statements out (`hide` by a regular expression, `ignore` for the calls of functions in `Func.ignore`).
- `grep(pattern: str, context: int = 2) -> str` The pseudocode lines that match a regular expression, with the lines around them.
- `save(path: str) -> str` Write the pseudocode to a file, replacing what it holds. Returns the file's absolute path.

### CItem

`CItem(item: citem_t, graph: DiGraph)` Represent an item inside a graph of a decompiled function.

- `id: int` Item object id.
- `address: int` Item address.
- `op: str` Name of the operation represented by this item.
- `op_id: int` The operation represented by this item.
- `type_name: str` The name of the type associated with this item.
- `accessed_struct: StrucT` Find and return the `StrucT` accessed by this memptr/memref operation.
- `accessed_struct_member: MemberT` Find and return the `MemberT` accessed by this memptr/memref operation.
- `called_function: Func` Find and return the `Func` called by this call operation.
- `num_value: int` Return the value corresponding to this num operation.
- `label: str` Short label for item.
- `children: List[CItem]` The children of this item.
- `n_children: int` The number of children of this item.
- `parent: CItem` The parent of this item.
- `parent_expression: CItem` Find and return the parent expression.
- `child_where(condition: Callable[[CItem], bool]) -> CItem` Preorder dfs search for the first child meeting the condition.
- `children_where(condition: Callable[[CItem], bool]) -> List[CItem]` Preorder dfs search for all children meeting the condition.
- `parent_where(condition: Callable[[CItem], bool]) -> CItem` Walk up the parents for the first one meeting the condition.
- `subtree_search_strict(query: Dict[str, Any]) -> List[List[List[CItem]]]` Perform a dfs tree search with the specified query.

### Call

`Call(site: int, kind: str, target: Func | None, text: str, args: Optional[List[str]] = None)` Represent one call that a function makes.

- `site: int` Address of the calling instruction.
- `kind: str` `'direct'`: a call instruction with a code reference. `'tail'`: a jump to the start of another function. `'indirect'`: a call instruction without a code reference, through a register or memory.
- `target: Func | None` The called function. `None` for an indirect call, or a target that is in no function.
- `text: str` The target's name (its address when it has none), or what an indirect call goes through: the operand such as `'X8'`, or the expression in a call from `CFunc.calls`.
- `args: Optional[List[str]]` The arguments as the pseudocode has them, in a call from `CFunc.calls`. `None` in a call from `Func.calls`, which reads the instructions.
- `to_dict() -> Dict[str, Any]` The call as a JSON-friendly `dict`, addresses as hex strings. `args` is there when the call has them.

### Functions and values

- `grep(pattern: str, funcs: Iterable[Address], context: int = 0, limit: int = None) -> str` The pseudocode lines of several functions that match a regular expression: `CFunc.grep` over each of them.
- `show_code(*targets, max_lines: int = 120, **options)` Print the pseudocode of one or more functions, each under a line with its address and name.
- `export_fingerprints(named_only: bool = True) -> Dict[str, str]` Fingerprints and names of the functions of this database, to find them in another build with `match_functions`.
- `match_functions(fingerprints: Dict[str, str]) -> Dict[int, str]` Find the functions of another build in this database, by fingerprint.

## misc

Provides helper functions that work on the whole database: symbols, names, comments and strings, and annotations in bulk.

### StringRef

`StringRef(address: Union[int, Pointer], text: str)` Represent one string of IDA's string list.

- `address: Pointer` Where the string starts.
- `text: str` The decoded string, without its terminator.
- `funcs: List[Func]` The functions that refer to the string, without duplicates and sorted by address.

### Functions and values

- `find_symbol(name: str) -> Pointer | None` The address of a name, `None` when the database has no such name. A name that is not there is tried with a leading underscore, so `main` finds a Mach-O file's `_main`.
- `search_names(pattern: str, limit: int = None) -> List[Pointer]` The addresses whose name matches a regular expression, in address order.
- `search_comments(pattern: str, limit: int = None, named_only: bool = True) -> List[Pointer]` The addresses whose comment matches a regular expression, in address order.
- `strings(pattern: str = None, encoding: str = None, refresh: bool = False) -> List[StringRef]` IDA's string list, C and UTF-16 strings, in address order.
- `describe(item: Any, width: int = None) -> str` One line that says what an object is, for a listing.
- `show(*items, limit: int = 40, width: int = 120)` Print objects one to a line, each as `describe` gives it.
- `rename_all(names: Dict[int, str], force: bool = True) -> int` Name many addresses, refreshing the decompiler once at the end.
- `comment_all(comments: Dict[int, str], repeatable: bool = True) -> int` Comment many addresses, refreshing the decompiler once at the end. A function's start gets a function comment, any other address an address comment.
- `annotate_all(items: Dict[int, Tuple[str | None, str | None]]) -> int` Name and comment many addresses, refreshing the decompiler once at the end.
- `export_annotations() -> Dict[str, Any]` What people and scripts added to the database, for `import_annotations` to apply to another copy of the same binary.
- `import_annotations(data: Dict[str, Any]) -> int` Apply what `export_annotations` returned, usually in another copy of the same binary. Refreshes the decompiler once at the end.

## struc

Provides class(es) for interacting with structures (definition and instances in memory).

### MemberT

`MemberT(id: int, struct: StrucT)` Represent a member of a struct type.

- `id: int` Member id (its tid).
- `struct: StrucT` The struct type containing this member.
- `udm: udm_t` The member as IDA describes it now, a fresh `ida_typeinf.udm_t` (offset and size in bits). Raises `IDAError` when the member is gone.
- `name: str` Member name.
- `dtype: tinfo_t` Member type, represented with `ida_typeinf.tinfo_t`.
- `offset: int` Member offset in struct, in bytes.
- `size: int` Member size in bytes. A bitfield counts the bytes its bits touch.
- `is_gap: bool` Whether the member is a gap: a single or array of `char` or `_BYTE`, with a name starting with `gap`.
- `instance_at(addr: Address) -> Any` Get the value from the given address.
- `instance_at_struct(struct_addr: Address) -> Any` Get the value from a struct at the given address.

### StrucT

`StrucT(target: Union[int, str, tinfo_t])` Represent a struct type, a struct or union of the database's local types.

- `id: int` Struct id (its tid).
- `StrucT.find(name: str) -> StrucT | None` Find struct type by name, `None` when there is none. `'struct Player'` works too, and a typedef name finds the struct it stands for.
- `StrucT.create(name: str) -> StrucT` Create and return an empty struct. Raises `IDAError` when the name is taken or not acceptable.
- `StrucT.parse(declaration: str) -> List[StrucT]` Declare types from C text, which may hold several declarations.
- `StrucT.import_header(path: str) -> int` Declare the types of a C header file, as File > Load file > Parse C header file does.
- `tif: tinfo_t` The type as IDA has it now. Editing this `ida_typeinf.tinfo_t` edits the type in the database. Raises `IDAError` when the type is gone.
- `name: str` Struct name.
- `declaration: str` The struct as C text, ready for `StrucT.parse`.
- `members: List[MemberT]` All member types of struct, in order. Gaps IDA keeps between members are members too.
- `size: int` Struct size in bytes.
- `instance_at(addr: Address) -> StrucI` Get an instance of this struct at the given address.
- `self[name]` Get a member type by name, `None` when there is none.
- `member_at_offset(offset: int) -> MemberT | None` Get the member type containing a byte offset, `None` when no member covers it.
- `member_starting_at_offset(offset: int) -> MemberT | None` Get a member type by offset, member must start at offset.
- `add_member(declaration: str, offset: int) -> MemberT` Create and return a new member in this struct type.
- `add_gap(offset: int, size: int) -> MemberT` Create and return a new member representing a bytes gap, `_BYTE gapXX[size]`.
- `delete_member(member: Union[MemberT, str]) -> bool` Delete a given member, or the member of that name. A member in the middle leaves a gap, the last one shrinks the struct.
- `add_member_auto(declaration: str, offset: int) -> MemberT` Create and return a new member in this struct type, automatically reworking gaps.

### StrucI

`StrucI(addr: Address, struc_t: Union[StrucT, str])` Represent a struct instance.

- `addr: Pointer` The address of this struct.
- `struc_t: StrucT` The type definition of this struct.
- `members: Dict[str, Any]` Collect all members of this struct as a dict of their values, reading the struct once.
- `to_dict() -> Dict[str, Any]` The members' values as a JSON-friendly `dict`: pointers as hex strings, a `char` array as its text up to the first zero, other bytes in hex, nested structs as dicts.
- `member(name: str, return_pointer: bool = True) -> Any` Get a member's `Pointer`, or its value with `return_pointer=False`. `None` when there is no such member.
- `ptr(name: str) -> Pointer` The address of a member. Raises `KeyError` when there is no such member.
- `self[name]` Get a member's value by its name.
- `self[name] = value` Set a member's value by its name, in the debugged process.

### Functions and values

- `parse_declaration(declaration: str) -> Tuple[tinfo_t, str]` Parse the C declaration of one member, such as `'unsigned int count'` or `'char name[16]'`.
- `apply_prototypes(prototypes: Dict[Address, str]) -> int` Apply C prototypes to functions, refreshing the decompiler once at the end.

## module

Provides class(es) for the modules of the debugged process: where each one is loaded, and how its addresses map to the database.

### Module

`Module(name: str, addr: int, size: int = 0)` Represent a module (the executable or a library) loaded in the debugged process.

- `static_bases: Dict[str, int]` The `Module.static_base` given to each module, by lowercase file name. Kept across `Module` objects, so it is set once per module.
- `name: str` Full path of the module, as the debugger reports it.
- `addr: int` Base address in the process.
- `size: int` Size in bytes, 0 when the debugger does not know it.
- `Module.all_modules() -> List[Module]` Every module of the debugged process, by address. `[]` when no process is being debugged.
- `Module.find(name: str) -> Module | None` The module with this full path or file name, ignoring case. `None` when it is not loaded.
- `Module.containing(addr: Address) -> Module | None` The module whose memory holds `addr`, `None` when there is none.
- `contains(addr: Address) -> bool` Whether `addr` is inside this module. Always false when the size is unknown.
- `is_input_file: bool` Whether this module is the file the database was made from.
- `static_base: int | None` [rw] Where the database has this module's base. Assign to set it, `None` to forget it.
- `to_static(addr: Address) -> int` Translate an address in the process to the matching address in the database.
- `from_static(ea: Address) -> Pointer` Translate an address in the database to the matching address in the process.
- `self + offset`

## debugger

Provides class(es) for driving the debugger: the process, breakpoints, registers and events.

### Event

`Event(kind: str, pid: int = 0, tid: int = 0, address: int | None = None, module: str | None = None, code: int | None = None, info: str = '')` Represent one event of the debugged process, such as a breakpoint hit or a library load.

- `kind: str` `'process_start'`, `'process_exit'`, `'library_load'`, `'library_unload'`, `'breakpoint'`, `'exception'`, `'thread_start'`, `'thread_exit'`, `'suspended'` or `'other'`.
- `pid: int` The process id.
- `tid: int` The thread the event happened in.
- `address: Pointer | None` Where it happened, `None` when IDA gives no address.
- `module: str | None` The module's path, for `'process_start'`, `'library_load'` and `'library_unload'`.
- `code: int | None` The exit code (`'process_exit'`, `'thread_exit'`) or the exception code (`'exception'`).
- `info: str` What else IDA said: the exception message, or the text of an `'other'` event.
- `suspends: bool` Whether this kind of event leaves the process suspended (see `SUSPENDING`).

### Debugger

`Debugger()` Drive IDA's debugger. There is one instance, `dbg`.

- `events: List[Event]` Every event since the first use (or `Debugger.clear_events`), oldest first.
- `event: Event | None` The latest event.
- `handler_error: BaseException | None` The exception the last failing handler raised. Cleared when `Debugger.resume`, `Debugger.wait` or the like starts waiting.
- `state: str` `'none'` (no process), `'running'` or `'suspended'`.
- `modules: List[Module]` The modules of the process, by address, as the load and unload events reported them.
- `threads: List[int]` Ids of the process's threads. `[]` when there is no process.
- `thread: int` [rw] The thread that registers are read from: the thread of the latest event, unless another one was assigned since. Assign a thread id to select it.
- `pc: Pointer` The program counter of `Debugger.thread`.
- `sp: Pointer` The stack pointer of `Debugger.thread`.
- `start(path: str, args: str = '', cwd: str = None, debugger: str = None, timeout: float = 10) -> Event` Start a process under the debugger and wait until it is suspended at its start.
- `attach(pid: int, debugger: str = None, timeout: float = 10) -> Event` Attach to a running process and wait until it is suspended.
- `wait(timeout: float = None) -> Event` Wait until the running process is suspended or exits, and return the event. Returns the latest event at once when the process is suspended already.
- `resume(timeout: float = None) -> Event | None` Continue the suspended process and wait until it is suspended again or exits.
- `run_to(target: Address, timeout: float = None) -> Event` Continue the suspended process until it reaches `target`, and return the event.
- `suspend() -> bool` Suspend the running process. Returns whether it is suspended. Raises `DebuggerError` when there is no process.
- `stop(timeout: float = 5) -> bool` Terminate the process. Returns `False` when there was none, `True` once it is gone.
- `detach() -> bool` Detach from the process and let it run on. Returns whether the debugger let go of it. Raises `DebuggerError` when there is no process.
- `reg(name: str, value: int = None) -> Union[int, float, bytes, bool]` Read/Write a register of `Debugger.thread`.
- `regs(*names) -> Dict[str, int]` Read several registers of `Debugger.thread` at once. Without names, every integer register the debugger can read.
- `stack(depth: int = 16) -> List[Pointer]` The call stack of `Debugger.thread`, innermost first: the current address, then the call instruction in each caller. At most `depth` entries.
- `call(target: Address, prototype: str, *args) -> Any` Call a function in the suspended process, on `Debugger.thread`, and return its result.
- `ref(value: Any = 0) -> Any` A by-reference argument for `Debugger.call`: the callee gets a pointer to a copy of `value`. Read `.value` afterwards for what it wrote there.
- `wide(text: str) -> bytes` A UTF-16 string argument for `Debugger.call`, with its terminator.
- `on(kind: str, handler: Callable[[Event], Any])` Call `handler(event)` for every event of this kind (one of `KINDS`). The return value is ignored. An exception goes to `Debugger.handler_error` and keeps the process suspended.
- `off(kind: str, handler: Callable = None)` Remove a handler given to `Debugger.on`, or every handler of this kind when `handler` is `None`.
- `clear_events()` Forget the recorded events. `Debugger.event` stays.

### Breakpoint

`Breakpoint(bpt: bpt_t)` Represent a breakpoint: at an address, or at an offset into a module (which may not be loaded yet).

- `key: tuple` What identifies the breakpoint: `('abs', address)`, `('rel', module file name, offset)`, `('sym', symbol, offset)` or `('src', file, line)`.
- `Breakpoint.add(target: Address, module: str = None, handler: Callable[[Event], Any] = None) -> Breakpoint` Add a breakpoint, or return the one already there.
- `Breakpoint.find(target: Address, module: str = None) -> Breakpoint | None` The breakpoint at an address, or at an offset into a module (by file name or full path, ignoring case). `None` when there is none.
- `Breakpoint.all() -> List[Breakpoint]` Every breakpoint IDA has.
- `Breakpoint.clear() -> int` Remove every breakpoint. Returns how many were removed.
- `bpt() -> bpt_t | None` IDA's current description of this breakpoint, `None` when it was removed.
- `remove() -> bool` Remove the breakpoint. Returns whether it was there.
- `enabled: bool` [rw] Whether the breakpoint is enabled. Assign to enable or disable it.
- `address: Pointer | None` Where the breakpoint is in the process. `None` while its module is not loaded, or once it is removed.
- `module: str | None` The module of a module-relative breakpoint, as IDA has it: the name it was added with, or the module's full path when IDA could only place it by that. `None` for any other breakpoint.
- `offset: int | None` The offset into the module of a module-relative breakpoint. `None` for any other breakpoint.
- `hits: int` How often the breakpoint was hit since the first use of `dbg`.
- `handler: Optional[Callable[[Event], Any]]` [rw] The function called on each hit, see `Breakpoint`. Assign to change it, `None` to remove it.

### Functions and values

- `dbg: Debugger` The debugger.

## utils

The errors the package raises, and helpers for showing results.

### IDAError

`IDAError()` Base class of the errors this package raises.

### DecompileError

`DecompileError()` The decompiler could not produce pseudocode.

### DebuggerError

`DebuggerError()` A debugger operation failed, or needed a process that is not there.

### Functions and values

- `hexdump(data, length = 16, sep = '.', start_offset = 0)`
- `jsonable(value: Any) -> Any` Convert a value to something `json.dumps` accepts. Addresses held by objects become hex strings.
