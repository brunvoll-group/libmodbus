#!/bin/bash
sudo apt install autoconf
./autogen.sh && ./configure && make && make install
