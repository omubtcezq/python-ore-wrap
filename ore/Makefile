CC = clang
INCPATHS = -I/usr/local/include
CFLAGS = -g -Wall -O3 $(INCPATHS) -march=native
LIBFLAGS = -fPIC -shared
LDLIBS = -lgmp -lssl -lcrypto
LDPATH = -L/usr/local/lib

BUILD = build
LIBBUILD = libbuild
TESTS = tests

SRC = crypto.c ore.c ore_blk.c
TESTPROGS = test_ore time_ore test_ore_blk time_ore_blk

OBJPATHS = $(patsubst %.c,$(BUILD)/%.o, $(SRC))
LIBPATHS = $(patsubst %.c,$(LIBBUILD)/%.so, $(SRC))
TESTPATHS = $(addprefix $(TESTS)/, $(TESTPROGS))

all: $(OBJPATHS) $(LIBPATHS) $(TESTPATHS)

obj: $(OBJPATHS)

lib: $(LIBPATHS)

$(BUILD):
	mkdir -p $(BUILD)

$(LIBBUILD):
	mkdir -p $(LIBBUILD)

$(TESTS):
	mkdir -p $(TESTS)

$(BUILD)/%.o: %.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ -c $<

$(LIBBUILD)/%.so: %.c | $(LIBBUILD)
	$(CC) $(CFLAGS) $(LIBFLAGS) -o $@ $<

$(TESTS)/%: %.c $(OBJPATHS) | $(TESTS)
	$(CC) $(CFLAGS) -o $@ $< $(LDPATH) $(OBJPATHS) $(LDLIBS)

clean:
	rm -rf $(BUILD) $(TESTS) $(LIBBUILD) *~
