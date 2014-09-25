client:
	gcc -ggdb -o bin/mtc -I ./headers  mtc.c bencode.c metafile.c peers.c sha1.c util.c pwp.c bf_logger.c -lcurl -lpthread -lrt

pwp_test:
	gcc -ggdb -o bin/pwp_test tests/pwp_test.c pwp.h bencode.h bencode.c util.h bf_logger.h -lpthread -lrt
