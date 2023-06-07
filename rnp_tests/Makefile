# Even though RNP exposes a C API, it's written in C++...
CC = g++

# We prefer GCC being pedantic uup front than incurring in common
	# pitfalls later down the road :)
CFLAGS = -Wall -Wextra

# Include paths
	# Note most of them are symlinked into /usr/local/include by Homebrew!
INCDIRS = $(addprefix -I, /usr/local/Cellar/zlib/1.2.12/include /usr/local/Cellar/bzip2/1.0.8/include)

# Library dependencies
	# Note most of them are symlinked into /usr/local/lib by Homebrew!
	# In order to generate a static binary you should pass the path to static libraries
	# (i.e. *.a) instead of flags in the usual `-l<name>` fashion.
LDDIRS = $(addprefix -L, /usr/local/Cellar/zlib/1.2.12/lib /usr/local/Cellar/bzip2/1.0.8/lib)
LDDEPS = $(addprefix -l, rnp botan-2 z bz2 json-c)
LDFLAGS = $(LDDIRS) $(LDDEPS)

PROGS = rnp_sample
TRASH = *.o *.asc

all: $(PROGS)

rnp_sample.ex: main.o keymgmt.o encrypt.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCDIRS) $(DBGFLAGS)

.PHONY: clean

clean:
	@rm -f $(PROGS) $(TRASH)