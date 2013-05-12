COMMON_FLAGS := -I /opt/crypto/include -g -Wall

CC       := /usr/local/gcc/bin/gcc
CFLAGS   := $(COMMON_FLAGS) --std=gnu99 

CXX      := /usr/local/gcc/bin/g++
CXXFLAGS := $(COMMON_FLAGS) --std=c++11

LDFLAGS := -L/opt/crypto/lib
LIBS    := -lssl -lcrypto -lrt

all : tok-sign sign encrypt OpenSSLWrappersTest

tok-sign : LIBS += -lp11

OpenSSLWrappersTest : LIBS += -lp11 -lboost_filesystem -lboost_system

OpenSSLWrappersTest : OpenSSLWrappersTest.o OpenSSLWrappers.o
	$(CXX) -o $@ $? $(CXXFLAGS) $(LDFLAGS) $(LIBS)

% : %.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS) $(LIBS)

%.o : %.cpp
	$(CXX) -c -o $@ $< $(CXXFLAGS)

clean :
	$(RM) encrypt sign tok-sign \
		*.o OpenSSLWrappersTest
