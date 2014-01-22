build: libcfed.so

libcfed.so: cfed_cleanup.o cfed_init.o cfed_spkigen.o cfed.o
	gcc -shared -o libcfed.so cfed.o cfed_init.o cfed_cleanup.o cfed_spkigen.o -lcurl

cfed.o: cfed.c cfed.h
	gcc cfed.c -c -fPIC -Wall -O0 -g

cfed_init.o: cfed_init.c cfed.h
	gcc cfed_init.c -c -fPIC -Wall -O0 -g

cfed_spkigen.o: cfed_spkigen.c cfed_spkigen.h cfed.h
	gcc cfed_spkigen.c -c -fPIC -Wall -O0 -g

cfed_cleanup.o: cfed_cleanup.c cfed.h
	gcc cfed_cleanup.c -c -fPIC -Wall -O0 -g

test: cfed_test.c cfed.h libcfed.so
	gcc cfed_test.c -L. -lcfed -Wall -O0 -g -o cfed_test

clean:
	rm -rf *.o *.so cfed_test
