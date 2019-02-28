#PREFIX is environment variable, but if it is not set, then set default value
ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

#Detect operating system
pgp_private_os := $(shell uname)
pgp_private_os := $(patsubst MINGW%,Windows,$(pgp_private_os))
pgp_private_os := $(patsubst CYGWIN%,Windows,$(pgp_private_os))
ifeq ($(pgp_private_os), Windows)
    pgp_os := windows
else ifeq ($(pgp_private_os), Darwin)
    pgp_os := macosx
else ifeq ($(pgp_private_os), Linux)
    pgp_os := linux
else
    $(info Warning: unknown OS, assuming linux)
    pgp_os := linux
endif
 os := $(pgp_os)

#set library extension
ifeq ($(os), windows)
    pgp_lib_extension := .dll
else ifeq ($(os), macosx)
    pgp_lib_extension := .dylib
else
    pgp_lib_extension := .so
endif

soext := $(pgp_lib_extension)

CARGO_SRC := $(CURDIR)/../Cargo.toml $(CURDIR)/../Cargo.lock
RUST_SRC := $(shell find $(CURDIR)/.. -name '*.rs')
LOCAL_SRC := build.rs librpgp.h

all: build

build: build-stamp
build-stamp: $(LOCAL_SRC) $(CARGO_SRC) $(RUST_SRC)
	cd $(CURDIR)/../ && cargo test --release -p pgp-ffi && cargo build --release -p pgp-ffi && cd pgp-ffi
	touch $@

install: build
	install -d $(DESTDIR)$(PREFIX)/lib/
	install -m 644 $(CURDIR)/../target/release/libpgp_ffi$(soext) $(DESTDIR)$(PREFIX)/lib/librpgp$(soext)
	install -d $(DESTDIR)$(PREFIX)/include/
	install -m 644 librpgp.h $(DESTDIR)$(PREFIX)/include/
	install -d $(DESTDIR)$(PREFIX)/lib/pkconfig
	install -m 644 $(CURDIR)/../target/release/pkgconfig/rpgp.pc $(DESTDIR)$(PREFIX)/lib/pkgconfig

clean:
	rm -f librpgp.h

.PHONY: clean build install
