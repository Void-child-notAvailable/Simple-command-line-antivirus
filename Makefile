CC = gcc
OUT_DIR = bin

all: $(OUT_DIR)/antivirus

$(OUT_DIR)/antivirus: src/antivirus.c | $(OUT_DIR)
	$(CC) $< -I/usr/include -lssl -lcrypto -lcurl -w -o $@
$(OUT_DIR):
	mkdir -p $(OUT_DIR)
clean:
	rm -rf $(OUT_DIR)
