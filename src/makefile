# Copyright (c) 2023 The MITRE Corporation. 
# ALL RIGHTS RESERVED. This copyright notice must 
# not be removed from this software, absent MITRE's 
# express written permission.

# use this directive in all .cpp files: #include "./pugixml-1.14/pugixml.hpp"

CC = g++
CFLAGS = -Wall -Wextra -g -std=c++17 -O2 -Wno-unused-parameter

BUILD_DIR = ../build
SRC_DIR = .
LIB_DIR = ../lib

# ****************************************************
# Targets needed to bring the executable up to date

all: main

main: $(BUILD_DIR)/main.o $(BUILD_DIR)/pugixml.o  $(BUILD_DIR)/ilf.o $(BUILD_DIR)/xml_translator.o
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o main $(BUILD_DIR)/main.o $(BUILD_DIR)/pugixml.o $(BUILD_DIR)/ilf.o $(BUILD_DIR)/xml_translator.o /usr/local/lib/libredis++.a /usr/local/lib/libhiredis.a -pthread

clean:
	rm -rf $(BUILD_DIR) \
	rm main

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.cpp
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/main.o -c $(SRC_DIR)/main.cpp

$(BUILD_DIR)/xml_translator.o: $(SRC_DIR)/xml_translator.cpp $(SRC_DIR)/xml_translator.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/xml_translator.o -c $(SRC_DIR)/xml_translator.cpp

$(BUILD_DIR)/pugixml.o: $(LIB_DIR)/pugixml-1.14/pugixml.cpp $(LIB_DIR)/pugixml-1.14/pugixml.hpp $(LIB_DIR)/pugixml-1.14/pugiconfig.hpp
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/pugixml.o -c $(LIB_DIR)/pugixml-1.14/pugixml.cpp

$(BUILD_DIR)/ilf.o: $(LIB_DIR)/libilf/ILF/ILF.cpp $(LIB_DIR)/libilf/ILF/ILF.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/ilf.o -c $(LIB_DIR)/libilf/ILF/ILF.cpp