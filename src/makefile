client:
	gcc -ggdb -o bin/client -I ./headers  client.c bencode.c metafile.h peers.h sha1.h util.h pwp.h bf_logger.h -lcurl -lpthread -lrt

pwp_test:
	gcc -ggdb -o bin/pwp_test tests/pwp_test.c pwp.h bencode.h bencode.c util.h bf_logger.h -lpthread -lrt
