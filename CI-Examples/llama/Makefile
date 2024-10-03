all: llama

LLAMA_REPO = https://github.com/ggerganov/llama.cpp
LLAMA_COMMIT = 90db8146d56d83a605f2c475eca39bcda29cf16d
LLAMA_TARGET = llama.cpp
LLAMA_TEMPLATE = llama-cli.manifest.template

.PHONY: llama
llama:
	if [ ! -e $(LLAMA_TARGET) ]; then \
		git clone $(LLAMA_REPO) $(LLAMA_TARGET) ; \
		cd $(LLAMA_TARGET) && git checkout $(LLAMA_COMMIT) ; \
	fi ;
	make -C $(LLAMA_TARGET)
	cp $(LLAMA_TARGET)/llama-cli .
	cp $(LLAMA_TEMPLATE) llama-cli.manifest


.PHONY: clean
clean:
	rm llama-cli llama-cli.manifest
