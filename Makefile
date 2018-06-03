output: main.o crysh.o
	cc -std=c99 -Wall -Werror -Wpedantic main.o crysh.o -g -o crysh -lssl -lcrypto

main.o: main.c
	cc -std=c99 -Wall -Werror -Wpedantic -g -c main.c -lssl -lcrypto

crysh.o: crysh.c crysh.h
	cc -std=c99 -Wall -Werror -Wpedantic -g -c crysh.c -lssl -lcrypto

clean:
	rm *.o crysh
