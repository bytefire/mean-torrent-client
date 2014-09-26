all: directories client

client:
	gcc -ggdb -o bin/mtc -I ./headers  mtc.c bencode.c metafile.c peers.c sha1.c util.c pwp.c bf_logger.c -lcurl -lpthread -lrt

directories:
	mkdir -p bin/logs
