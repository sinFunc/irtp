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
include tests/CMakeFiles/test_suite_cipher.gcm.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include tests/CMakeFiles/test_suite_cipher.gcm.dir/compiler_depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/test_suite_cipher.gcm.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/test_suite_cipher.gcm.dir/flags.make

tests/test_suite_cipher.gcm.c: ../tests/scripts/generate_test_code.py
tests/test_suite_cipher.gcm.c: library/libmbedtls.a
tests/test_suite_cipher.gcm.c: ../tests/suites/helpers.function
tests/test_suite_cipher.gcm.c: ../tests/suites/main_test.function
tests/test_suite_cipher.gcm.c: ../tests/suites/host_test.function
tests/test_suite_cipher.gcm.c: ../tests/suites/test_suite_cipher.function
tests/test_suite_cipher.gcm.c: ../tests/suites/test_suite_cipher.gcm.data
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating test_suite_cipher.gcm.c"
	cd /home/sean/installBySrc/mbedtls-2.28.3/build/tests && /usr/bin/python3.10 /home/sean/installBySrc/mbedtls-2.28.3/tests/scripts/generate_test_code.py -f /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_cipher.function -d /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_cipher.gcm.data -t /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/main_test.function -p /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/host_test.function -s /home/sean/installBySrc/mbedtls-2.28.3/tests/suites --helpers-file /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/helpers.function -o .

tests/CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.o: tests/CMakeFiles/test_suite_cipher.gcm.dir/flags.make
tests/CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.o: tests/test_suite_cipher.gcm.c
tests/CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.o: tests/CMakeFiles/test_suite_cipher.gcm.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object tests/CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.o"
	cd /home/sean/installBySrc/mbedtls-2.28.3/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT tests/CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.o -MF CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.o.d -o CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.o -c /home/sean/installBySrc/mbedtls-2.28.3/build/tests/test_suite_cipher.gcm.c

tests/CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.i"
	cd /home/sean/installBySrc/mbedtls-2.28.3/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/sean/installBySrc/mbedtls-2.28.3/build/tests/test_suite_cipher.gcm.c > CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.i

tests/CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.s"
	cd /home/sean/installBySrc/mbedtls-2.28.3/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/sean/installBySrc/mbedtls-2.28.3/build/tests/test_suite_cipher.gcm.c -o CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.s

# Object files for target test_suite_cipher.gcm
test_suite_cipher_gcm_OBJECTS = \
"CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.o"

# External object files for target test_suite_cipher.gcm
test_suite_cipher_gcm_EXTERNAL_OBJECTS = \
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
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test.dir/tests/src/threading_helpers.c.o" \
"/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles/mbedtls_test_helpers.dir/tests/src/test_helpers/ssl_helpers.c.o"

tests/test_suite_cipher.gcm: tests/CMakeFiles/test_suite_cipher.gcm.dir/test_suite_cipher.gcm.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/asn1_helpers.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/drivers/hash.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/drivers/platform_builtin_keys.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_aead.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_cipher.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_key_management.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_mac.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_signature.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/drivers/test_driver_size.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/fake_external_rng_for_test.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/helpers.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/psa_crypto_helpers.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/psa_exercise_key.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/random.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test.dir/tests/src/threading_helpers.c.o
tests/test_suite_cipher.gcm: CMakeFiles/mbedtls_test_helpers.dir/tests/src/test_helpers/ssl_helpers.c.o
tests/test_suite_cipher.gcm: tests/CMakeFiles/test_suite_cipher.gcm.dir/build.make
tests/test_suite_cipher.gcm: library/libmbedtls.a
tests/test_suite_cipher.gcm: library/libmbedx509.a
tests/test_suite_cipher.gcm: library/libmbedcrypto.a
tests/test_suite_cipher.gcm: tests/CMakeFiles/test_suite_cipher.gcm.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/sean/installBySrc/mbedtls-2.28.3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable test_suite_cipher.gcm"
	cd /home/sean/installBySrc/mbedtls-2.28.3/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_suite_cipher.gcm.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/test_suite_cipher.gcm.dir/build: tests/test_suite_cipher.gcm
.PHONY : tests/CMakeFiles/test_suite_cipher.gcm.dir/build

tests/CMakeFiles/test_suite_cipher.gcm.dir/clean:
	cd /home/sean/installBySrc/mbedtls-2.28.3/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/test_suite_cipher.gcm.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/test_suite_cipher.gcm.dir/clean

tests/CMakeFiles/test_suite_cipher.gcm.dir/depend: tests/test_suite_cipher.gcm.c
	cd /home/sean/installBySrc/mbedtls-2.28.3/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/sean/installBySrc/mbedtls-2.28.3 /home/sean/installBySrc/mbedtls-2.28.3/tests /home/sean/installBySrc/mbedtls-2.28.3/build /home/sean/installBySrc/mbedtls-2.28.3/build/tests /home/sean/installBySrc/mbedtls-2.28.3/build/tests/CMakeFiles/test_suite_cipher.gcm.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/test_suite_cipher.gcm.dir/depend

