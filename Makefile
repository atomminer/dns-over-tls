resolver: resolver.o dns.o
	gcc -o resolver resolver.o dns.o -lstdc++ -lssl -lcrypto

resolver.o: resolver.cpp 
	gcc -c resolver.cpp

dns.o: dns.cpp dns.h
	gcc -c dns.cpp

clean:
	rm -rf ./*.o
	rm -rf ./resolver
