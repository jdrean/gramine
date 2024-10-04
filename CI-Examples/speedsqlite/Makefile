all: speedsqlite

.PHONY: speedsqlite
speedsqlite:
	cp speedtest1.manifest.template speedtest1.manifest
	rm -rf build
	mkdir -p build
	cd build && ../sqlite/configure --enable-all
	make -C build/ sqlite3 speedtest1
	cp build/speedtest1 .

.PHONY: clean
clean:
	@rm -rf speedtest1.manifest build speedtest1

.PHONY: distclean
distclean: clean
