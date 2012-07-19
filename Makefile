all:
	cc -Wall -c cinepy.c
	cc -shared -Wall -o cinepy.so *.o -lcrypto
	cc -o cinepy-cmd cinepy.c -lcrypto
