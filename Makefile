CXX=c++

resolver: resolver.o dns.o
	$(CXX) -o resolver resolver.o dns.o -lssl -lcrypto

resolver.o: resolver.cpp 
	$(CXX) -c resolver.cpp

dns.o: dns.cpp dns.h
	$(CXX) -c dns.cpp

clean:
	rm -rf ./*.o
	rm -rf ./resolver
