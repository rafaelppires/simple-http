
test:
	g++ -std=c++11 test.cpp -o test -I. http1decoder.cpp httprequest.cpp httpresponse.cpp stringutils.cpp httpheaders.cpp httpurl.cpp httpcommon.cpp

run: test
	valgrind --leak-check=full ./test

clean:
	rm test

.PHONY: test run clean

