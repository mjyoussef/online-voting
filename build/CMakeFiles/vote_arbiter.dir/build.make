# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/cs1515-user/final-myousse2

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/cs1515-user/final-myousse2/build

# Include any dependencies generated for this target.
include CMakeFiles/vote_arbiter.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/vote_arbiter.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/vote_arbiter.dir/flags.make

CMakeFiles/vote_arbiter.dir/src/cmd/arbiter.cxx.o: CMakeFiles/vote_arbiter.dir/flags.make
CMakeFiles/vote_arbiter.dir/src/cmd/arbiter.cxx.o: ../src/cmd/arbiter.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/cs1515-user/final-myousse2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/vote_arbiter.dir/src/cmd/arbiter.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/vote_arbiter.dir/src/cmd/arbiter.cxx.o -c /home/cs1515-user/final-myousse2/src/cmd/arbiter.cxx

CMakeFiles/vote_arbiter.dir/src/cmd/arbiter.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/vote_arbiter.dir/src/cmd/arbiter.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/cs1515-user/final-myousse2/src/cmd/arbiter.cxx > CMakeFiles/vote_arbiter.dir/src/cmd/arbiter.cxx.i

CMakeFiles/vote_arbiter.dir/src/cmd/arbiter.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/vote_arbiter.dir/src/cmd/arbiter.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/cs1515-user/final-myousse2/src/cmd/arbiter.cxx -o CMakeFiles/vote_arbiter.dir/src/cmd/arbiter.cxx.s

# Object files for target vote_arbiter
vote_arbiter_OBJECTS = \
"CMakeFiles/vote_arbiter.dir/src/cmd/arbiter.cxx.o"

# External object files for target vote_arbiter
vote_arbiter_EXTERNAL_OBJECTS =

vote_arbiter: CMakeFiles/vote_arbiter.dir/src/cmd/arbiter.cxx.o
vote_arbiter: CMakeFiles/vote_arbiter.dir/build.make
vote_arbiter: libvote_app_lib.a
vote_arbiter: libvote_app_lib_shared.a
vote_arbiter: /usr/lib/aarch64-linux-gnu/libboost_system.a
vote_arbiter: /usr/lib/aarch64-linux-gnu/libboost_log_setup.a
vote_arbiter: /usr/lib/aarch64-linux-gnu/libboost_log.a
vote_arbiter: /usr/lib/aarch64-linux-gnu/libboost_thread.a
vote_arbiter: /usr/lib/aarch64-linux-gnu/libboost_filesystem.a
vote_arbiter: /usr/lib/aarch64-linux-gnu/libboost_atomic.a
vote_arbiter: /usr/lib/aarch64-linux-gnu/libboost_chrono.a
vote_arbiter: /usr/lib/aarch64-linux-gnu/libboost_date_time.a
vote_arbiter: /usr/lib/aarch64-linux-gnu/libboost_regex.a
vote_arbiter: /usr/lib/aarch64-linux-gnu/libcurses.so
vote_arbiter: /usr/lib/aarch64-linux-gnu/libform.so
vote_arbiter: CMakeFiles/vote_arbiter.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/cs1515-user/final-myousse2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable vote_arbiter"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/vote_arbiter.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/vote_arbiter.dir/build: vote_arbiter

.PHONY : CMakeFiles/vote_arbiter.dir/build

CMakeFiles/vote_arbiter.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/vote_arbiter.dir/cmake_clean.cmake
.PHONY : CMakeFiles/vote_arbiter.dir/clean

CMakeFiles/vote_arbiter.dir/depend:
	cd /home/cs1515-user/final-myousse2/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/cs1515-user/final-myousse2 /home/cs1515-user/final-myousse2 /home/cs1515-user/final-myousse2/build /home/cs1515-user/final-myousse2/build /home/cs1515-user/final-myousse2/build/CMakeFiles/vote_arbiter.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/vote_arbiter.dir/depend

