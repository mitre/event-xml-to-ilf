# Copyright (c) 2023 The MITRE Corporation. 
# ALL RIGHTS RESERVED. This copyright notice must 
# not be removed from this software, absent MITRE's 
# express written permission.

# Note: use this directive in all .cpp files: 
# add #include "../lib/pugixml-1.14/pugixml.hpp"

CC = g++
CFLAGS = -Wall -Wextra -g -std=c++17 -O2 -Wno-unused-parameter

BUILD_DIR = ../build
CUR_DIR = .
SRC_DIR = ../src
LIB_DIR = ../lib

# ****************************************************
# Targets needed to bring the executable up to date

all: test

test: $(BUILD_DIR)/test.o $(BUILD_DIR)/pugixml.o  $(BUILD_DIR)/ilf.o $(BUILD_DIR)/xml_translator.o
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o test $(BUILD_DIR)/test.o $(BUILD_DIR)/pugixml.o $(BUILD_DIR)/ilf.o $(BUILD_DIR)/xml_translator.o /usr/local/lib/libredis++.a /usr/local/lib/libhiredis.a

clean:
	rm -rf $(BUILD_DIR) \
	rm test

$(BUILD_DIR)/test.o: $(CUR_DIR)/test.cpp
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/test.o -c $(CUR_DIR)/test.cpp

$(BUILD_DIR)/xml_translator.o: $(SRC_DIR)/xml_translator.cpp $(SRC_DIR)/xml_translator.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/xml_translator.o -c $(SRC_DIR)/xml_translator.cpp

$(BUILD_DIR)/pugixml.o: $(LIB_DIR)/pugixml-1.14/pugixml.cpp $(LIB_DIR)/pugixml-1.14/pugixml.hpp $(LIB_DIR)/pugixml-1.14/pugiconfig.hpp
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/pugixml.o -c $(LIB_DIR)/pugixml-1.14/pugixml.cpp

$(BUILD_DIR)/ilf.o: $(LIB_DIR)/libilf/ILF/ILF.cpp $(LIB_DIR)/libilf/ILF/ILF.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/ilf.o -c $(LIB_DIR)/libilf/ILF/ILF.cpp