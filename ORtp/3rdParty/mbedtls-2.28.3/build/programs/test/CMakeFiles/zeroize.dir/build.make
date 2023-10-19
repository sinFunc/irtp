# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
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
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/sean/installBySrc/mbedtls-2.28.3

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/sean/installBySrc/mbedtls-2.28.3/build

# Include any dependencies generated for this target.
include programs/test/CMakeFiles/zeroize.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include programs/test/CMakeFiles/zeroize.dir/compiler_depend.make

# Include the progress variables for this target.
include programs/test/CMakeFiles/zeroize.dir/progress.make

# Include the compile flags for this target's objects.
include programs/test/CMakeFiles/zeroize.dir/flags.make

programs/test/CMakeFiles/zeroize.dir/zeroize.c.o: programs/test/CMakeFiles/zeroize.dir/flags.make
programs/test/CMakeFiles/zeroize.dir/zeroize.c.o: ../programs/test/zeroize.c
programs/test/CMakeFiles/zeroize.dir/zeroize.c.o: programs/test/CMakeFiles/zeroize.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object programs/test/CMakeFiles/zeroize.dir/zeroize.c.o"
	cd /home/sean/installBySrc/mbedtls-2.28.3/build/programs/test && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT programs/test/CMakeFiles/zeroize.dir/zeroize.c.o -MF CMakeFiles/zeroize.dir/zeroize.c.o.d -o CMakeFiles/zeroize.dir/zeroize.c.o -c /home/sean/installBySrc/mbedtls-2.28.3/programs/test/zeroize.c

programs/test/CMakeFiles/zeroize.dir/zeroize.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/zeroize.dir/zeroize.c.i"
	cd /home/sean/installBySrc/mbedtls-2.28.3/build/programs/test && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/sean/installBySrc/mbedtls-2.28.3/programs/test/zeroize.c > CMakeFiles/zeroize.dir/zeroize.c.i

programs/test/CMakeFiles/zeroize.dir/zeroize.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/zeroize.dir/zeroize.c.s"
	cd /home/sean/installBySrc/mbedtls-2.28.3/build/programs/test && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/sean/installBySrc/mbedtls-2.28.3/programs/test/zeroize.c -o CMakeFiles/zeroize.dir/zeroize.c.s

# Object files for target zeroize
zeroize_OBJECTS = \
"CMakeFiles/zeroize.dir/zeroize.c.o"

# External object files for target zeroize
zeroize_EXTERNAL_OBJECTS = \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/asn1_helpers.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/drivers/hash.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/drivers/platform_builtin_keys.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_aead.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_cipher.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_key_management.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_mac.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_signature.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_size.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/fake_external_rng_for_test.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/helpers.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/psa_crypto_helpers.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/psa_exercise_key.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/random.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/threading_helpers.c.o"

programs/test/zeroize: programs/test/CMakeFiles/zeroize.dir/zeroize.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/asn1_helpers.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/drivers/hash.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/drivers/platform_builtin_keys.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_aead.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_cipher.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_key_management.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_mac.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_signature.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_size.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/fake_external_rng_for_test.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/helpers.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/psa_crypto_helpers.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/psa_exercise_key.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/random.c.o
programs/test/zeroize: CMakeFiles/mbedtls_test.dir/tests/src/threading_helpers.c.o
programs/test/zeroize: programs/test/CMakeFiles/zeroize.dir/build.make
programs/test/zeroize: library/libmbedcrypto.a
programs/test/zeroize: programs/test/CMakeFiles/zeroize.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable zeroize"
	cd /home/sean/installBySrc/mbedtls-2.28.3/build/programs/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/zeroize.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
programs/test/CMakeFiles/zeroize.dir/build: programs/test/zeroize
.PHONY : programs/test/CMakeFiles/zeroize.dir/build

programs/test/CMakeFiles/zeroize.dir/clean:
	cd /home/sean/installBySrc/mbedtls-2.28.3/build/programs/test && $(CMAKE_COMMAND) -P CMakeFiles/zeroize.dir/cmake_clean.cmake
.PHONY : programs/test/CMakeFiles/zeroize.dir/clean

programs/test/CMakeFiles/zeroize.dir/depend:
	cd /home/sean/installBySrc/mbedtls-2.28.3/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/sean/installBySrc/mbedtls-2.28.3 /home/sean/installBySrc/mbedtls-2.28.3/programs/test /home/sean/installBySrc/mbedtls-2.28.3/build /home/sean/installBySrc/mbedtls-2.28.3/build/programs/test /home/sean/installBySrc/mbedtls-2.28.3/build/programs/test/CMakeFiles/zeroize.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : programs/test/CMakeFiles/zeroize.dir/depend

