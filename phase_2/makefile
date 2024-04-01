BUILD_DIR=build
AFL_SETTINGS=AFL_IMPORT_FIRST=1 AFL_TESTCACHE_SIZE=50MB AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1
ALF_BUILD_ENV=AFL_CC_COMPILER=LLVM AFL_LLVM_INSTRUMENT=LTO #AFL_LLVM_DENYLIST=denylist.txt

all: $(BUILD_DIR)/test

.PHONY:
clean:
	rm -rf build crashes

start_fuzz:
	tmux new -s fuzz \
		' \
			tmux select-layout tiled \
			&& tmux split-window -v "make start_main_fuzz" \
			&& tmux split-window -h "make start_sanitizer_fuzz" \
			&& tmux split-window -v "make start_laf_fuzz" \
			&& tmux split-window -h "make start_cmplog_fuzz" \
			&& tmux split-window -v "make start_mopt_fuzz" \
			&& tmux split-window -v "make start_explore_fuzz" \
			&& tmux split-window -v "make start_exploit_fuzz" \
		'

restart_fuzz:
	tmux new -s fuzz \
		' \
			tmux select-layout tiled \
			&& tmux split-window -v "make restart_main_fuzz" \
			&& tmux split-window -h "make restart_sanitizer_fuzz" \
			&& tmux split-window -v "make restart_laf_fuzz" \
			&& tmux split-window -h "make restart_cmplog_fuzz" \
			&& tmux split-window -v "make restart_mopt_fuzz" \
			&& tmux split-window -v "make restart_explore_fuzz" \
			&& tmux split-window -v "make restart_exploit_fuzz" \
		'

$(BUILD_DIR)/fuzz: fuzz.cpp two4Tree.cpp
	mkdir -p build
	g++ fuzz.cpp -O3 -o $(BUILD_DIR)/fuzz

$(BUILD_DIR)/fuzz_debug: fuzz.cpp two4Tree.cpp
	mkdir -p build
	g++ fuzz.cpp -g -o $(BUILD_DIR)/fuzz_debug

$(BUILD_DIR)/test: test.cpp two4Tree.cpp
	mkdir -p build
	g++ test.cpp -O3 -o $(BUILD_DIR)/test
	
phase_2: Phase2Main.cpp two4Tree.cpp 
	mkdir -p build
	g++ Phase2Main.cpp -O3 -o $(BUILD_DIR)/Phase2Main

phase_2_debug: Phase2Main.cpp two4Tree.cpp 
	mkdir -p build
	g++ Phase2Main.cpp -g -o $(BUILD_DIR)/Phase2Main

$(BUILD_DIR)/main_fuzz: fuzz.cpp two4Tree.cpp
	mkdir -p build
	$(ALF_BUILD_ENV) afl-c++ fuzz.cpp -o $(BUILD_DIR)/main_fuzz -march=native -O3

$(BUILD_DIR)/sanitizer_fuzz: fuzz.cpp two4Tree.cpp
	mkdir -p build
	$(ALF_BUILD_ENV) AFL_USE_UBSAN=1 AFL_USE_ASAN=1 afl-c++ fuzz.cpp -o $(BUILD_DIR)/sanitizer_fuzz -march=native -O3

$(BUILD_DIR)/laf_fuzz: fuzz.cpp two4Tree.cpp
	mkdir -p build
	$(ALF_BUILD_ENV) AFL_LLVM_LAF_ALL=1 afl-c++ fuzz.cpp -o $(BUILD_DIR)/laf_fuzz -march=native -O3

$(BUILD_DIR)/cmplog_fuzz: fuzz.cpp two4Tree.cpp
	mkdir -p build
	$(ALF_BUILD_ENV) AFL_LLVM_CMPLOG=1 afl-c++ fuzz.cpp -o $(BUILD_DIR)/cmplog_fuzz -march=native -O3

start_main_fuzz: $(BUILD_DIR)/main_fuzz
	$(AFL_SETTINGS) AFL_FINAL_SYNC=1 afl-fuzz -i inputs -o ramdisk -M main-wks001 -a binary -- ./$(BUILD_DIR)/main_fuzz @@

start_sanitizer_fuzz: $(BUILD_DIR)/sanitizer_fuzz
	$(AFL_SETTINGS) afl-fuzz -i inputs -o ramdisk -S sanitizer-wks001 -a binary -- ./$(BUILD_DIR)/sanitizer_fuzz @@

start_laf_fuzz: $(BUILD_DIR)/laf_fuzz
	$(AFL_SETTINGS) afl-fuzz -i inputs -o ramdisk -S laf-wks001 -a binary -- ./$(BUILD_DIR)/laf_fuzz @@

start_cmplog_fuzz: $(BUILD_DIR)/cmplog_fuzz
	$(AFL_SETTINGS) AFL_MAP_SIZE=1M afl-fuzz -i inputs -o ramdisk -S cmplog-wks001 -c $(BUILD_DIR)/cmplog_fuzz -l 2AT -a binary -- ./$(BUILD_DIR)/main_fuzz @@

start_mopt_fuzz: $(BUILD_DIR)/main_fuzz
	$(AFL_SETTINGS) afl-fuzz -i inputs -o ramdisk -M mopt-wks001 -L 0 -a binary -- ./$(BUILD_DIR)/main_fuzz @@

start_explore_fuzz: $(BUILD_DIR)/main_fuzz
	$(AFL_SETTINGS) afl-fuzz -i inputs -o ramdisk -M explore-wks001 -P explore -a binary -- ./$(BUILD_DIR)/main_fuzz @@

start_exploit_fuzz: $(BUILD_DIR)/main_fuzz
	$(AFL_SETTINGS) afl-fuzz -i inputs -o ramdisk -M exploit-wks001 -P exploit -a binary -- ./$(BUILD_DIR)/main_fuzz @@

restart_main_fuzz: $(BUILD_DIR)/main_fuzz
	AFL_FAST_CAL=1 AFL_CMPLOG_ONLY_NEW=1 $(AFL_SETTINGS) AFL_FINAL_SYNC=1 afl-fuzz -i - -o ramdisk -M main-wks001 -a binary -- ./$(BUILD_DIR)/main_fuzz @@

restart_sanitizer_fuzz: $(BUILD_DIR)/sanitizer_fuzz
	AFL_FAST_CAL=1 AFL_CMPLOG_ONLY_NEW=1 $(AFL_SETTINGS) afl-fuzz -i - -o ramdisk -S sanitizer-wks001 -a binary -- ./$(BUILD_DIR)/sanitizer_fuzz @@

restart_laf_fuzz: $(BUILD_DIR)/laf_fuzz
	AFL_FAST_CAL=1 AFL_CMPLOG_ONLY_NEW=1 $(AFL_SETTINGS) afl-fuzz -i - -o ramdisk -S laf-wks001 -a binary -- ./$(BUILD_DIR)/laf_fuzz @@

restart_cmplog_fuzz: $(BUILD_DIR)/cmplog_fuzz
	AFL_FAST_CAL=1 AFL_CMPLOG_ONLY_NEW=1 AFL_MAP_SIZE=1M $(AFL_SETTINGS) afl-fuzz -i - -o ramdisk -S cmplog-wks001 -c $(BUILD_DIR)/cmplog_fuzz -l 2AT -a binary -- ./$(BUILD_DIR)/main_fuzz @@

restart_mopt_fuzz: $(BUILD_DIR)/main_fuzz
	AFL_FAST_CAL=1 AFL_CMPLOG_ONLY_NEW=1 $(AFL_SETTINGS) afl-fuzz -i - -o ramdisk -M mopt-wks001 -L 0 -a binary -- ./$(BUILD_DIR)/main_fuzz @@

restart_explore_fuzz: $(BUILD_DIR)/main_fuzz
	AFL_FAST_CAL=1 AFL_CMPLOG_ONLY_NEW=1 $(AFL_SETTINGS) afl-fuzz -i - -o ramdisk -M explore-wks001 -P explore -a binary -- ./$(BUILD_DIR)/main_fuzz @@

restart_exploit_fuzz: $(BUILD_DIR)/main_fuzz
	AFL_FAST_CAL=1 AFL_CMPLOG_ONLY_NEW=1 $(AFL_SETTINGS) afl-fuzz -i - -o ramdisk -M exploit-wks001 -P exploit -a binary -- ./$(BUILD_DIR)/main_fuzz @@
