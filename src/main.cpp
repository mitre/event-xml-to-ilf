/*
    Copyright (c) 2023 The MITRE Corporation. 
    ALL RIGHTS RESERVED. This copyright notice must 
    not be removed from this software, absent MITRE's 
    express written permission.
*/

// *IMPORTANT*: User to comment or uncomment the '#define WINDOWS` variable before compiling to ensure program is compilable on Windows or Linux.
// #define WINDOWS 

#include <iostream>
#include <stdio.h>
#include <string>
#include "xml_translator.h"

XML_TO_ILF *translator = NULL;

#ifdef WINDOWS
    #include "windows_wrapper.h"
#endif

/*
    Example program using the Sysmon XML to ILF translator. Demonstrates how to read from a file or
    stream and how to reference the configuration files.

    Usage:
        # From a file
        ./main -m <field_mappings.json> \
            -f <allowed_fields.json> \
            -e <event_names.json> \
            -l <log_file.xml> \
            -s <sleep_time_in_ms> \
        
        # From standard in
        cat <log_file.xml> | ./main \ 
            -m <field_mappings.json> \
            -f <allowed_fields.json> \
            -e <event_names.json> \
            -l stdin \
            -s <sleep_time_in_ms> \
*/


int main (int argc, char *argv[])
{
    translator = new XML_TO_ILF(argc, argv);

    // for Windows use only, live extraction of logs
    if (translator->get_stream_type() == "live") {
        #ifdef WINDOWS
            windows_stream_wrapper();
        #endif
    
    // reading from standard in
    } else if (translator->get_stream_type() == "stdin") {
        translator->run_from_stdin(cin);
    
    // assumes a file path has been passed on the command line
    } else {
        translator->run();
    }

    // if (redis != nullptr) {
    //     delete redis;
    // }

    translator->~XML_TO_ILF();
    return 0;
}