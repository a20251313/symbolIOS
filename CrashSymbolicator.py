import sys
sys.path.append("/Applications/Xcode.app/Contents/SharedFrameworks/CoreSymbolicationDT.framework/Versions/A/Resources/")
import libatos
import JSONCrashLog
import argparse
import os
import pathlib
import json
import uuid
import pprint
import copy
import concurrent.futures


'''
JSON crash log symbolication tool.
'''

def image_paths_with_search_directory(image, search_path, crash):
	if not search_path:
		directories = JSONCrashLog.device_support_directories_for_crash(crash)
	else:
		directories = [search_path]

	image_path = pathlib.Path(image.path)
	path_joiner = lambda parent_dir :  pathlib.Path(parent_dir) / image_path.relative_to(image_path.anchor)
	return [path_joiner(directory) for directory in list(directories)]

def session_for_image(image, dsym, search_path, crash, verbose):
	# Create a symbolication session for the image. 
	# First, we'll try using the image's reported path
	# directly as a source for symbols. 

	# This would only yield a valid session on the same
	# device that the crash happened on. If we're symbolicating
	# e.g. an iOS  crash log on a Mac, then the paths won't
	# match. In that case, we'll also try creating the path from 
	# the search path.


	# Without a UUID, an arch, or path in the images list, we can't
	# reliably create a symbolication session.
	if not hasattr(image, 'uuid'):
		return None

	if not hasattr(image, 'arch'):
		return None

	if not hasattr(image, 'path'):
		return None

	image_uuid = uuid.UUID(image.uuid)
	image_arch = libatos.Architecture.from_architecture_string(image.arch)
	image_path = image.path

	session = libatos.CreateSessionWithPathArchitectureAndUUID(image_path, image_arch, image_uuid)
	if session:
		# Using the path directly found a valid binary
		if verbose:
			print("Found binary {} with arch {} and UUID {}".format(image_path, image.arch, image_uuid))
		return session

	# Couldn't create a valid session from the given path. Try again with
	# the search directory. 
	image_paths = image_paths_with_search_directory(image, search_path, crash)
	for image_path in image_paths:
		# Try to create a session for each of the known search paths.
		# If we get a valid session from one of these search paths, then
		# we return that session.
		session = libatos.CreateSessionWithPathArchitectureAndUUID(str(image_path), image_arch, image_uuid)
		if session:
			if verbose:
				print("Found binary in extra search directory {} with arch {} and UUID {}".format(image_path, image.arch, image_uuid))
			return session

	# Try using the dSYM search path to find a DWARF binary matching the image
	dsym_search_path = debugsymbols_search_directory_for_dsym(dsym)
	if not dsym_search_path:
		return None

	# Find all paths in the dsym search directory that match "DWARF/image_name"
	matching_dwarf_binaries = dsym_search_path.rglob("DWARF/{}".format(image.name))
	for dwarf_binary in matching_dwarf_binaries:
		session = libatos.CreateSessionWithPathArchitectureAndUUID(str(dwarf_binary), image_arch, image_uuid)
		if session:
			if verbose:
				print("Found dwarf binary {} with arch {} and UUID {}".format(dwarf_binary, image.arch, image_uuid))
			return session

	return None

def symbolication_sessions_for_images(crash, dsym, search_path, verbose):
	# Try to create a libatos symbolication session for each of the used images.

	sessions = [session_for_image(image, dsym, search_path, crash, verbose) for image in crash.usedImages()]

	# Next, instruct Spotlight to consider the dsym path for symbolication
	dsym_search_path = debugsymbols_search_directory_for_dsym(dsym)
	if dsym_search_path:
		if verbose:
			print("Adding {} to debug symbol search path".format(dsym_search_path))
		for session in sessions:
			libatos.AddDsymSearchPaths(session, [str(dsym_search_path)])

	return sessions

def debugsymbols_search_directory_for_dsym(dsym):
	if not dsym:
		return None

	# If the specified dsym path refers to a dSYM directly, then we
	# need to return its containing directory to DebugSymbols.
	# Otherwise, if it refers to a directory of dSYMs, we return the
	# path directly.

	resolved = dsym.expanduser()
	extension = resolved.suffix
	if extension == ".dSYM":
		return resolved.parent
	else:
		return resolved

def create_argument_parser():
	parser = argparse.ArgumentParser(description="Symbolicate a crash log")
	parser.add_argument("-d", "--dsym", dest="dsym", metavar="dSYM", type=pathlib.Path, help="Path to a dSYM file or a directory of dSYM files for symbolication")
	parser.add_argument("-s", "--search-dir", dest="search_dir", metavar="SEARCH_PATH", type=pathlib.Path, help="Additional search paths in which to search for symbol rich binaries")
	parser.add_argument("-o", "--output", dest="output", metavar="OUTPUT_FILE", type=argparse.FileType('w'), default="-", help="Location to store symbolicated crash log. Defaults to stdout")
	parser.add_argument("-p", "--pretty", dest="pretty", action="store_true", default=False, help="Format the symbolicated crash log via pretty print")
	parser.add_argument("-w", "--workers", dest="workers", metavar="N", default=0, type=int, help="Symbolicate the thread backtraces in parallel using the specified number of workers")
	parser.add_argument("--no-inlines", dest="no_inlines", action="store_true", default=False, help="Don't include inlined functions in the symbolicated log")
	parser.add_argument("--no-source-info", dest="no_source_info", action="store_true", default=False, help="Don't include source information such as file name and line number in the symbolicated log")
	parser.add_argument("--only-missing", dest="only_missing", action="store_true", default=False, help="Only symbolicate backtrace frames that don't have symbol names")
	parser.add_argument("--no-system-frameworks", dest="no_system_frameworks", action="store_true", default=False, help="Don't symbolicate frames for system frameworks")
	parser.add_argument("--no-demangle", dest="no_demangle", action="store_true", default=False, help="Don't demangle symbol names in the symbolicated log")
	parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Display verbose information about symbolicating the crash logs" )
	parser.add_argument("crash_log", metavar="LOGFILE", type=argparse.FileType('r'), help="The crash log to be symbolicated. Specify either a path to the crash log or '-' for stdin")

	return parser


def create_frames_from_symbol(symbol, old_frame, address, args):
	if not symbol:
		# no symbol, can't create a frame for it
		return []

	frames = []
	frame = copy.deepcopy(old_frame)
	if args.no_demangle:
		symbol_name = symbol.mangled_name
	else:
		symbol_name = symbol.name

	if symbol_name:
		frame.symbol = symbol_name.decode('utf-8')

	source_info = symbol.source_info
	if source_info and not args.no_source_info:
		frame.sourceFile = source_info.filename().decode('utf-8')
		frame.sourceLine = source_info.line_number

	# Record the offset of the address within the bounds of the identified symbol
	frame.symbolLocation = address - symbol.address_range.location
	frames.append(frame)
	
	if not args.no_inlines:
		# Recursively create frames for inlined symbols
		inlined_frames = create_frames_from_symbol(symbol.inlined_symbol, old_frame, address, args)
		for inlined_frame in inlined_frames:
			inlined_frame.inline = "true"
		frames.extend(inlined_frames)

	return frames


def create_frames_from_symbolication_result(result, old_frame, address, args):

	# Structure of a frame
	'''
	   {
		  "imageOffset": <Offset>,
		  "symbol": <symbol name>,
		  "symbolLocation": <offset of the address from the start of the symbol>,
		  "imageIndex": <index>
		  "sourceFile" : <filename>
		  "sourceLine" : <line number>
		}
	 '''
	
	# If there was no result from libatos, or if the result
	# has a null symbol, then just return the original frame.
	if not result:
		return [old_frame]
	if not result.symbols:
		return [old_frame]
	if len(result.symbols) == 1 and not result.symbols[0]:
		return [old_frame]

	# Otherwise, construct a list with each resulting frame.
	frames = []
	for symbol in result.symbols:
		frames.extend(create_frames_from_symbol(symbol, old_frame, address, args))

	return frames

def is_frame_symbolicated(frame):
	# If this frame already has a symbol name,
	# then it's symbolicated.
	return hasattr(frame, 'symbol')

def is_system_framework(path):
	if not path:
		return False

	system_prefixes = ["/System/", "/Applications/", "/usr/", "/bin/", "/usr/lib/", "/Library/", "/AppleInternal/"]
	return any(path.startswith(prefix) for prefix in system_prefixes)

def is_frame_inlined(frame):
	return hasattr(frame, "inline")


def should_symbolicate_frame(frame, images, args):
	# Determine if this frame should be processed for
	# symbolication info. 
	imageIndex = frame.imageIndex
	if imageIndex < 0 or imageIndex > len(images):
		# Can't get an image for this frame. Don't attempt to symbolicate it.
		return False

	image = images[imageIndex]
	imagePath = image.path
	if not imagePath:
		# No image path, don't attempt to symbolicate.
		return False

	is_sys_framework = is_system_framework(imagePath)
	is_symbolicated = is_frame_symbolicated(frame)

	if is_sys_framework and args.no_system_frameworks:
		# This current frame references a system framework, but we were instructed
		# to not symbolicate system frameworks.
		return False

	if is_symbolicated and args.only_missing:
		# This current frame is already symbolicated, but we we were instructed
		# to only symbolicate frames with missing symbol info.
		return False

	if is_frame_inlined(frame):
		# Don't resymbolicate an inlined frame. If the input frame is marked as inlined
		# then it was generated from DWARF data, and we can't do better than that.
		return False


	return True

def is_new_inlined_callstack_better_than_old_callstack(new_inlined_callstack, old_inlined_callstack):
	# Heuristics for determining whether an existing inlined callstack 
	# should be replaced with a new inlined callstack.

	if not new_inlined_callstack:
		return False

	if len(new_inlined_callstack) != len(old_inlined_callstack):
		return True

	# Compare each frame in the new and old callstacks. 
	# If we have differing source info 
	for new_frame, old_frame in zip(new_inlined_callstack, old_inlined_callstack):
		new_source_file = getattr(new_frame, "sourceFile", None)
		new_source_line = getattr(new_frame, "sourceLine", None)
		old_source_file = getattr(old_frame, "sourceFile", None)
		old_source_line = getattr(old_frame, "sourceLine", None)

		# If we couldn't generate any source info for the new frame,
		# but the old frame did have source info, then don't replace
		# the existing callstack.
		if new_source_file is None and old_source_file is not None:
			return False

		if new_source_line is None and old_source_line is not None:
			return False

		# Otherwise, if the new source info differs from the old source info,
		# then replace the existing callstack.
		if new_source_file != old_source_file or new_source_line != old_source_line:
			return True

	return False

def adjust_from_return_address(address, frame_index, old_inlined_callstack_length):
	
	if frame_index - old_inlined_callstack_length == 0:
		# Topmost entry in the backtrace; so this isn't a return address
		return address

	return address - 1 # Subtract one to end up with the address of the call instruction.

def symbolicate_backtrace(symbolication_sessions, frames, crash, args):
	# Symbolicates each frame in the supplied `frames` list, which represents a backtrace.
	# Each frame has enough information to determine the address to
	# undergo symbolication. This address is supplied to the frame
	# image's symbolication session.

	symbolicated_frames = []
	images = crash.usedImages()

	# If we're resymbolicating a crash log that had some amount of symbolication already
	# performed, such as inlined frame expansion, then we need to make sure we don't just
	# try resymbolicating every frame. The existing inlined callstacks are recorded in 
	# `old_inlined_callstack`. Once we reach the end of the inlined callstack and are now
	# looking at the concrete/"parent" frame, then we'll compare the old inlined callstack
	# to the new inlined callstack that we get from symbolicating this concrete/"parent" frame.
	# We only keep the better of the two. 

	old_inlined_callstack = []
	for frame_index, frame in enumerate(frames):
		imageIndex = frame.imageIndex
		if imageIndex > len(images):
			if verbose:
				print("Skipping symbolication for frame {} because its image index, {}, is out of bounds.".format(frame, imageIndex))
			continue

		# For each frame, determine which image it refers to and calculate the address that
		# should ungergo symbolication. The frame's image index is also used to access the
		# appropriate symbolication session. 

		image = images[imageIndex]
		imageBaseAddress = image.base
		offsetFromBaseAddress = frame.imageOffset
		address = imageBaseAddress + offsetFromBaseAddress
		adjusted_address = adjust_from_return_address(address, frame_index, len(old_inlined_callstack))
		if should_symbolicate_frame(frame, images, args):

			session = symbolication_sessions[imageIndex]
			if image.source == 'T':
				# This is a TEXT-EXEC image. Make sure to use "__TEXT_EXEC" as the base segment
				result = libatos.SymbolicateAddressWithLoadAddressAndSegment(session, adjusted_address, imageBaseAddress, "__TEXT_EXEC")
			else:
				# No segment name is specified here (though it's probably safe to use "__TEXT"). This will instruct libatos
				# to use the lowest vmaddr segment it finds (excluding PAGEZERO) as the base segment.
				result = libatos.SymbolicateAddressWithLoadAddress(session, adjusted_address, imageBaseAddress)

			new_frames = create_frames_from_symbolication_result(result, frame, adjusted_address, args)
			concrete_frame = new_frames[0]
			new_inlined_frames = new_frames[1:] # We're guaranteed to have at least one result. Inlined frames will start at index 1.

			# Reverse the list of inlined frames so that any inlined functions are ordered before the
            # concrete symbols. E.g. if new_frames contains symbols such as [parent_function, inlined_child1, inlined_child2],
            # then we want to examine the callstack in the following order:
            #
            # inlined_child_2 foo.cpp:10
            # inlined_child_1 foo.cpp:42
            # parent_function foo.cpp:64
			new_inlined_frames.reverse() 
			
			if args.verbose:
				print("Symbolicating frame {}  {{ image = {}, base address = {}, desired address = {} }}".format(frame_index, image.name, hex(imageBaseAddress), hex(adjusted_address)))

			if is_new_inlined_callstack_better_than_old_callstack(new_inlined_frames, old_inlined_callstack):
				# The new inlined callstack is better than the old one, so we keep the results that we just 
				# symbolicated
				if args.verbose:
					new_inlined_frame_count = len(new_inlined_frames)
					print("Replacing previous {} inlined frames with {} new inlined frames".format(len(old_inlined_callstack), new_inlined_frame_count))

			else:
				# Keep the previous inlined frames instead of the new ones.
				new_inlined_frames = old_inlined_callstack
				if args.verbose:
					print("Keeping previous {} inlined frames".format(len(old_inlined_callstack)))

			symbolicated_frames.extend(new_inlined_frames)
			symbolicated_frames.append(concrete_frame)

			# By definition of should_symbolicate_frame(), we'll never directly symbolicate
			# a frame which has the 'inline:true' attribute. So, this branch of the if() statement
			# above will never be entered when examining an inlined frame. As such, we can clear
			# our current view of the old_inlined_callstack.
			old_inlined_callstack.clear()
		else:
			if args.verbose:
				print("Skipping symbolication for frame {} {{ image = {}, base address = {}, desired address = {} }}".format(frame_index, image.name, hex(imageBaseAddress), hex(adjusted_address)))
			if is_frame_inlined(frame):
				# Keep track of this inlined frame
				old_inlined_callstack.append(frame)
			else:
				symbolicated_frames.append(frame)

	return symbolicated_frames

def symbolicate_thread_backtrace(symbolication_sessions, thread, crash, args):
	# Symbolicates the frames for the supplied thread and returns a dictionary
	# mapping the thread's id to the symbolicated frames.
	print("Symbolicating thread {}".format(thread.id))
	symbolicated_frames = symbolicate_backtrace(symbolication_sessions, thread.frames, crash, args)
	return { thread.id : symbolicated_frames }


def symbolicate_thread_backtraces(symbolication_sessions, crash, args):
	# Each image in the usedImages will have a symbolication session
	
	symbolicated_thread_frames = {}
	if args.workers <= 1:
		# Don't symbolicate in parallel.
		for thread in crash.thread_backtraces():
			symbolicated_frames = symbolicate_thread_backtrace(symbolication_sessions, thread, crash, args)
			symbolicated_thread_frames.update(symbolicated_frames)
	else:
		if args.verbose:
			print("Spawning up to {} threads for symbolication", args.workers)
		with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
			symbolicated_frame_futures = [ executor.submit(symbolicate_thread_backtrace, symbolication_sessions, thread, crash, args) for thread in crash.thread_backtraces() ]
			for future in concurrent.futures.as_completed(symbolicated_frame_futures):
				symbolicated_frames = future.result()
				symbolicated_thread_frames.update(symbolicated_frames)
	return symbolicated_thread_frames


def symbolicate_last_exception_backtrace(symbolication_sessions, crash, args):
	# Not associated with any particular thread, but it shares
	# the same structure as the the thread backtraces. 

	leb = crash.lastExceptionBacktrace()
	if not leb:
		return None
	
	symbolicated_leb = symbolicate_backtrace(symbolication_sessions, leb, crash, args)
	return symbolicated_leb


def update_thread_backtraces(crash, new_backtraces):
	for thread in crash.thread_backtraces():
		key = thread.id
		backtrace = new_backtraces[key]
		if backtrace:
			thread.frames = backtrace

def update_last_exception_backtrace(crash, new_leb):
	if not new_leb:
		return
	else:
		crash.updateLastExceptionBacktrace(new_leb)


def symbolicate(args):

	crash_log_file = args.crash_log
	crash_log = JSONCrashLog.JSONCrashLog(crash_log_file)

	if args.verbose:
		with_dsym = args.dsym is not None
		with_search_path = args.search_dir is not None
		only_missing = args.only_missing
		no_inlines = args.no_inlines
		no_source_info = args.no_source_info
		if with_dsym:
			print("Symbolicating with dSYM search path: {}".format(args.dsym))

		if with_search_path:
			print("Symbolicating with extra search path: {}".format(args.search_dir))
		else:
			print("Symbolicating with default search paths")


		if only_missing:
			print("Skipping symbolication for frames with existing symbol info")

		if no_inlines:
			print("Omitting inlined frames")

		if no_source_info:
			print("Omitting source info")

	# Create the symbolication sessions for each image identified in the crash log
	sessions = symbolication_sessions_for_images(crash_log, args.dsym, args.search_dir, args.verbose)

	symbolicated_thread_backtraces = symbolicate_thread_backtraces(sessions, crash_log, args)
	update_thread_backtraces(crash_log, symbolicated_thread_backtraces)

	symbolicated_leb = symbolicate_last_exception_backtrace(sessions, crash_log, args)
	update_last_exception_backtrace(crash_log, symbolicated_leb)

	crash_log.write_to(args.output, args.pretty)
	args.output.close()
	args.crash_log.close()	

	for session in sessions:
		libatos.DestroySymbolicationSession(session)

def SymbolicateCrashWithArgs(args):
	# If another module wants to symbolicate a crash log,
	# they can call into this function with the supplied arguments
	# as a list (e.g. ["-d", "<dSYM path>", "--pretty", "<logfile>"])
	parser = create_argument_parser()
	args = parser.parse_args(args)

	symbolicate(args)

if __name__ == "__main__":
	# If the python script is invoked directly, parse the arguments from the command line
	parser = create_argument_parser()
	args = parser.parse_args()
	symbolicate(args)