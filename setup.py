application_title = "log_to_csv"
main_python_file = "csvfile.py"

import sys

from cx_Freeze import setup, Executable

base = None
if sys.platform == "win32":
	base = "Win32GUI"
	
includes = ['atexit','re',]

setup(
	name=application_title,
	version="1",
	description="test",
	options={"build_exe":{"includes":includes}},
	executables=[Executable(main_python_file, base=base)]
)