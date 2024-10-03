# LLama port to gramine (for Tyche)

Do a `make`, it will clone llama-cpp here and checkout a commit I have worked with and tested.
It will build llama.cpp and extract the binary we want (llama-cli).

The make command also generate the necessary manifest (it's just a cp of the .template).
I prefilled everything with the configuration that works.


When running, use the following command:

```
/gramine/gramine-tyche llama-cli -m /llama-small.gguf --log-disable -n 100 -t 1 --no-mmap --ctx-size 256 --prompt "Your prompt goes here"
```

This will only output the model's reply.
If you want to have the logging, remove the `--log-disable` variable.
Llama will then output the token stats at the end of the computation.



We expect gramine to be installed at `gramine` and your model to be at `/model/llama-small.gguf`.
The model I used can be downloaded here:

```
https://huggingface.co/hugging-quants/Llama-3.2-1B-Instruct-Q4_K_M-GGUF/resolve/main/llama-3.2-1b-instruct-q4_k_m.gguf?download=true
```

The main page is here:

```
https://huggingface.co/hugging-quants/Llama-3.2-1B-Instruct-Q4_K_M-GGUF/tree/main
```

If you are running as part of `tyche-bench`, the justfile should take care of downloading the model for you and putting it inside the to-copy folder.
