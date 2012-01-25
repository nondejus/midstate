all:
	gcc -std=c99 -shared midstatemodule.c -Wl,-O1 -Wl,--as-needed -fPIC -lpython3.2 -o midstate.so
	gcc -std=c99 midstatemodule.c -Wl,-O1 -Wl,--as-needed -fPIC -lpython3.2 -o main
