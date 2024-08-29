all: build-tyche

build-tyche:
	if [ -n -e $(TYCHE_ROOT) ]; then \
		echo "Missing/Incorrect TYCHE_ROOT"; \
		exit 1; \
	fi
	if [ -n -e $(TARGET) ]; then \
		echo "Missing/Incorrect TARGET"; \
		exit 1 ; \
	fi
	meson setup build-port/ -Ddirect=enabled -Dtyche=enabled -Dtyche_drivers=$(TYCHE_ROOT)/linux/drivers/ \
		-Dtyche_backend=tyche -Dtyche_sdk=$(TYCHE_ROOT)/C/libraries/sdktyche \
		-Dtyche_pts=$(TYCHE_ROOT)/C/libraries/pts --bindir=$(TARGET) --prefix=$(TARGET)
	ninja -C build-port/ && sudo ninja -C build-port install

.PHONY: clean

clean:
	rm -rf build-port
