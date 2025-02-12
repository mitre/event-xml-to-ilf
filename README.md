# Sysmon XML to ILF Translator
This C++ program translates [Windows Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) event logs from their native XML format to MITRE'S ILF. The program supports reading logs from an XML file directly or piped from standard in (useful when processing very large files), as well as in real-time from the Sysmon event producer (Windows only). All translated events are sent to Redis, which can be configured using a file located in the the `sysmon_configurations` module. 

The program leverages many open source libraries, including the XML DOM parser [pugixml](https://pugixml.org/), JSON for C++, redis++ and hiredis.

# Configuration Files
The translator **requires** configuration files to function, which it expects to reside in the `sysmon_configuration` module. These files specify which fields of the Sysmon events to process and which ECS (Elastic Common Schema) fields it should map the them to. 

Please refer to that module's [README](https://github.com/mitre/sysmon-config) for further information about them and how to generate them. 

**Notes:** 

- ECS uses a `@timestamp` field which cannot be included in the ILF attributes list as `@` is not supported. The translator does not prevent this so beware of your configuration choices!
- In ECS mappings, periods (`.`) denote hierachies and are replaced with double underscores (`__`) in the ILF as periods are not allowed.

# Program Arguments
The translator takes exactly 4 arguments, in any order, on the command line:
```
- m     specifying the field Mappings json 
- f     specifying the allowed Fields json
- e     specifying the Event names json
- l     specifying the source of Logs: either "stdin", "live" or a path to an XML file
- s     specifying the time in milliseconds to sleep between logs sent to redis
```
**Note:** `stdin` is useful when replaying logs in a very large file so that the XML parser only buffers one line at a time rather than the entire file.

# Windows
## Windows Log Streamer
The translator leverages code from the Microsoft online documentation for the Windows Event Log API and is modified to work with the ILF translator.

It allows the translator to subscribe to, and process, Sysmon events in real-time via the channel `Microsoft-Windows-Sysmon/Operational`.

The original source can be found [here](https://learn.microsoft.com/en-us/windows/win32/wes/subscribing-to-events) under the `Push Subscriptions` section.

## Compiling on Windows
On Windows, do not use the provided `makefile`. It is only for compiling on Linux.

### **IMPORTANT**
Before compiling on Windows, make sure to *uncomment* the line at the top of `main.cpp` as this will make available the `windows_streamer_wrapper.h` file required for the live extraction of logs:
```
#define WINDOWS
```

Then use the CMakeLists.txt file to compile using vcpkg: 

```sh
cmake --preset=default # Installs dependencies and generates build files
cmake --build build # Compiles build files into main.exe
``` 

The outputted executable file can be found at `/build/Debug`.

## Running the Translator on Windows
**Note:** Provide files names, not file paths.

### Translating event logs from a small file
```
./main.exe -m <field_mappings.json> \
    -f <allowed_fields.json> \
    -e <event_names.json> \
    -l <log_file.xml> \
    -s <sleep_time_in_ms>
```

### Translating event logs from standard in (cin) for large log files
**Note**: The use of a stream from which to process Sysmon events is specified by the string `stdin` for the `-l` flag.
```
cat <log_file.xml> | ./main.exe \ 
    -m <field_mappings.json> \
    -f <allowed_fields.json> \
    -e <event_names.json> \
    -l stdin \
    -s <sleep_time_in_ms>
```

### Translating event live logs as they are processed by Sysmon
 In this mode, the program translates all current events in the channel and any future events that are raised while the application is active.

 The use of a live stream from which to process Sysmon events is specified by the string `live` for the `-l` flag.

```
./main.exe \ 
    -m <field_mappings.json> \
    -f <allowed_fields.json> \
    -e <event_names.json> \
    -l live \
    -s <sleep_time_in_ms>
```

# Compiling and Running on Linux
**NOTE**: Live log extraction is only available on Windows.

Use the provided `makefile`

Use the same commands as listed for Windows but replace `main.exe` with `main`.

## Running the Tests on Linux
From the `./test` directory

Use the provided `makefile` to build and link the dependencies.

### Reading hardcoded logs
Run `./test` to use the hardcoded files in `./input-logs`

### Reading from `cin` stream
**Note:** Uncomment the function call `test_streaming_cin()` and `make` the program again

Run `cat <file_name> | ./test`

`All tests passed!` should result from a successful run.

## License

This software is licensed under the Apache 2.0 license.

## Public Release

> [!NOTE]
> Approved for Public Release; Distribution Unlimited. Public Release Case
> Number 24-3961.
