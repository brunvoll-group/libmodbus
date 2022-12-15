#!/bin/bash
./autogen.sh && ./configure --prefix=/home/cecco/local/ CFLAGS='-g -O0 -DDEBUG=1' && make && make install