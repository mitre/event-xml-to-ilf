/*
    Copyright (c) 2023 The MITRE Corporation. 
    ALL RIGHTS RESERVED. This copyright notice must 
    not be removed from this software, absent MITRE's 
    express written permission.
*/

/*
    Header file for the class encapsulating the translator for Sysmon XML events to ILF.
*/  

#include <iostream>
#include <fstream>
#include <sstream>
#include <ostream>
#include <string.h>
#include <stdio.h>
#include <map>
#include <algorithm>
#include <cctype> 
#include <utility>
#include <regex>
#include <sw/redis++/redis++.h>

#include "../lib/pugixml-1.14/pugixml.hpp"
#include "../lib/json/single_include/nlohmann/json.hpp"
#include "../lib/libilf/ILF/ILF.h"

using namespace std;
using namespace pugi;
using json = nlohmann::json;

#define HASHES "Hashes"
#define HASH "Hash"
#define USER "User"

class XML_TO_ILF {
    public:
        XML_TO_ILF(int argc, char *argv[]);
        XML_TO_ILF(json _allowed_fields_json, json _event_names_json, 
                   json _field_mappings_json, string _xml_logs_path, json _redis_json);

        ~XML_TO_ILF();

        int run();
        int run_from_stdin(istream &);
        int run_from_string(string event_string) ;
        ILF *process_event(xml_node);

        // For testing
        json get_allowed_fields_json() const;
        json get_field_mappings_json() const;
        json get_event_names_json() const;
        
        const xml_document *get_root() const;
        int get_num_events_processed();
        static string replace_periods(string);
        string get_stream_type();
    
    private:
        // Object holding the XML tree
        xml_document root;

        // Whether or not the translator reads from a stream
        string stream_type;

        // JSON objects to store configuration files data
        json allowed_fields_json, field_mappings_json, event_names_json, redis_json;
        
        // Variables to store the configuration files and the XML event log paths provided by user on CLI
        // Default values
        string xml_logs_path = "stdin";
        string allowed_fields_config_path = "allowed_fields.json"; 
        string field_mappings_config_path = "field_mappings.json"; 
        string event_names_config_path = "event_names.json";
        int sleep_duration = 0;

        // Base paths
        string event_names_base_path    = "../lib/sysmon_configurations/name-mappings-configs/";
        string allowed_fields_base_path = "../lib/sysmon_configurations/allowed-field-configs/";
        string field_mappings_base_path = "../lib/sysmon_configurations/field-mappings-configs/";
        string redis_config_path        = "../lib/sysmon_configurations/redis/redis_config.json";

        // Counter to track the number of events processed
        int num_events_processed;

        typedef struct sysmon_xml {
            string id;
            string event_name;
            string sender; 
            string receiver;
            string time;
            vector<key_val> event_data;
        } sysmon_xml;

        sw::redis::ConnectionOptions redis_connection_options;
        sw::redis::Redis *redis;
        string redis_channel;
        void setup_redis();
        
        void import_configs();
        void import_config(string, json &);
        void load_event_file(string xml_logs_path);
        void get_event_data(xml_node, map<string, string> *);
        bool get_event_metadata(sysmon_xml *, xml_node) ;
        void get_field_values(sysmon_xml *, map<string, string> *);
        void get_1_many_fields(map<string, pair<string, string>> *, string);
        void parse_XML_hashes(stringstream &, map<string, pair<string, string>> &, sysmon_xml *);
        void parse_XML_user(stringstream &, map<string, pair<string, string>> &, sysmon_xml *);
        string parse_args(int argc, char *argv[]);
        bool parse_arg(int, char *[], const string &, string &);
        bool isNumber(const string&);
        string quote_string(string, bool isHash = false);
};


