/*
    Copyright (c) 2023 The MITRE Corporation. 
    ALL RIGHTS RESERVED. This copyright notice must 
    not be removed from this software, absent MITRE's 
    express written permission.
*/

/*
    Class definition encapsulating the translator for Sysmon XML events to ILF.
*/
#include "xml_translator.h"

// Constructor reads in command line arguments containing paths to configuration and 
// event log files.
XML_TO_ILF::XML_TO_ILF(int argc, char *argv[])
{   
    num_events_processed = 0;

    stream_type = parse_args(argc, argv);
    import_configs();
    
    if (stream_type != "stdin" && stream_type != "live")
        load_event_file(xml_logs_path);

    setup_redis();
}

// Constructor reads in configurations from JSON objects directly.
XML_TO_ILF::XML_TO_ILF(json _allowed_fields_json, json _event_names_json, 
                       json _field_mappings_json, string _xml_logs_path, json _redis_json)
{
    num_events_processed = 0;

    allowed_fields_json = _allowed_fields_json;
    event_names_json    = _event_names_json;
    field_mappings_json = _field_mappings_json;
    xml_logs_path       = _xml_logs_path;

    redis_json = _redis_json;

    load_event_file(xml_logs_path);
    
    setup_redis();

    // from_stream = "false";
}

XML_TO_ILF::~XML_TO_ILF()
{
    if (redis != nullptr) 
    {
        // Close the redis connection and free the pointer
        delete redis;
        redis = nullptr;
    }
}

string XML_TO_ILF::get_stream_type()
{
    return stream_type;
}

void XML_TO_ILF::setup_redis()
{
    if (redis_json == NULL || redis_json == "")
        return;

    redis_connection_options.port = redis_json["port"];
    redis_connection_options.host = redis_json["host"];
    redis_connection_options.password = redis_json["password"];
    redis_channel = redis_json["channel"];

    redis = new sw::redis::Redis(redis_connection_options);
}

// Loads the XML event file into a pugixml structure
void XML_TO_ILF::load_event_file(string xml_logs_path)
{
    if (!root.load_file(xml_logs_path.c_str())) {
        cerr << "Error opening the event log file at " << xml_logs_path << endl;
        exit(EXIT_FAILURE);
    }
}

// Process all XML events
int XML_TO_ILF::run()
{   
    if (stream_type == "stdin" || stream_type == "live") {
        cerr << "Use run_from_stream() instead." << endl;
        exit(EXIT_FAILURE);
    }

    for (xml_node event_node : root.child("Events").children()) {
        ILF *ilf = process_event(event_node);
        if (ilf == nullptr) {
            continue;
        }
        cout << ilf->to_string() << endl;
        num_events_processed++;
        
        redis->publish(redis_channel, ilf->to_string().c_str());
        delete ilf;
        
        if (sleep_duration > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(sleep_duration));
        }
    }

    return 0;
}

// Process events individually from standard in (cin)
int XML_TO_ILF::run_from_stdin(istream &stream)
{
    if (stream_type != "stdin") {
        cerr << "Can only use this function if processing events from standard in (cin)" << endl;
        exit(EXIT_FAILURE);
    }
    
    string event_string;
    while (getline(stream, event_string))
    {
        run_from_string(event_string);
    }
    return 0;
}

// Process a single event represented as a string
int XML_TO_ILF::run_from_string(string event_string) 
{
    if (!root.load_string(event_string.c_str())) {
        cerr << "Error loading the event string: " << event_string << endl;
    }

    ILF *ilf = process_event(root.first_child());
    if (ilf == nullptr) {
        return 0;
    }
    
    cout << ilf->to_string() << endl << endl;
    num_events_processed++;
    
    redis->publish(redis_channel, ilf->to_string().c_str());
    delete ilf;
    
    if (sleep_duration > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_duration));
    }

    return 0;
}

// Returns the root of the parsed XML tree
const xml_document* XML_TO_ILF::get_root() const
{
    return &root;
}

// Returns the number of processed XML events
int XML_TO_ILF::get_num_events_processed()
{
    return num_events_processed;
}

// processing an event involves extracting the data from the Sysmon XML event object
// and mapping it to the ECS schema per the configuration files.
ILF *XML_TO_ILF::process_event(xml_node event_node)
{
    sysmon_xml *event_xml = new sysmon_xml;
    if (event_xml == NULL) {
        cerr << "Error allocating memory for event_xml" << endl;
        exit(EXIT_FAILURE);
    }

    map<string, string> event_data;

    bool found_id = get_event_metadata(event_xml, event_node);

    if (!found_id)
    {
        delete event_xml;
        return nullptr;
    }

    get_event_data(event_node, &event_data);
    get_field_values(event_xml, &event_data);

    ILF *ilf = new ILF(event_xml->event_name, 
                    event_xml->sender, 
                    "*", 
                    event_xml->time, 
                    event_xml->event_data);
    
    delete event_xml;
    
    return ilf;
}

// gets and stores event metadata (id, event_name, sender, time) in the sysmon_xml object
bool XML_TO_ILF::get_event_metadata(sysmon_xml *event_xml, xml_node event_node)
{
    event_xml->id = event_node.child("System").child("EventID").text().get();
    event_xml->event_data.push_back(key_val("event__code", event_xml->id));

    event_xml->sender = event_node.child("System").child("Computer").text().get();
    event_xml->time = event_node.child("System").child("TimeCreated").attribute("SystemTime").value();

    try {
        event_xml->event_name = event_names_json.at(event_xml->id);
    } catch (const json::out_of_range &e) {
        cerr << "Exception in get_event_metadata() for event #: " << event_xml->id << ". " << e.what() << endl;
        return false;
    }
    return true;
}

// loops through the allowed Sysmon fields specified in the config file for this event, maps them
// to their corresponding ECS fields, finds their values in the given event data map, and adds them
// to the sysmon_xml object's vector of attributes.
void XML_TO_ILF::get_field_values(sysmon_xml *event_xml, map<string, string> *event_data)
{
    for (string allowed_field : allowed_fields_json.at(event_xml->id)) {
        try {
            string &allowed_field_value = event_data->at(allowed_field);

            // get the mapping to the ECS field for the allowed Sysmon field
            auto ecs_field_object = field_mappings_json.at(event_xml->id).at(allowed_field);

            // Case 1: ECS field is a string
            if (!ecs_field_object.is_array()) {
                event_xml->event_data.push_back(key_val(replace_periods(ecs_field_object), 
                                                        quote_string(allowed_field_value)));
            
            // Case 2: ECS field is an array of strings (1:many mapping)
            } else {
                map<string, pair<string, string>> allowed_ecs_map;
                
                auto ecs_fields = ecs_field_object.template get<vector<string>>();
                for (auto ecs_field_name : ecs_fields)
                    get_1_many_fields(&allowed_ecs_map, ecs_field_name);
                
                // parse the XML values for the Sysmon fields "Hashes", "Hash", "User"
                stringstream allowed_field_value_stream(allowed_field_value);
                if (allowed_field == HASHES || allowed_field == HASH)
                    parse_XML_hashes(allowed_field_value_stream, allowed_ecs_map, event_xml);
                else if (allowed_field == USER)
                    parse_XML_user(allowed_field_value_stream, allowed_ecs_map, event_xml);
            }       
        } catch(...) { }
    }
}

// parses the text in the XML data node for the "User" field, delimited by a '\',
// and adds the field values to the map of allowed user fields.
// also adds them to the event_xml struct.
void XML_TO_ILF::parse_XML_user(stringstream &allowed_field_value_stream, 
                    map<string, pair<string, string>> &allowed_user_fields_map, 
                    sysmon_xml *event_xml)
{
    string domain, name;
    getline(allowed_field_value_stream, domain, '\\');
    
    // no value present for this field in XML event
    if (domain == "-")
        return;

    getline(allowed_field_value_stream, name);

    try{
        allowed_user_fields_map.at("name").second   = name;
        allowed_user_fields_map.at("domain").second = domain;
    } catch (...) { }

    for (auto &e: allowed_user_fields_map) {
        event_xml->event_data.push_back(key_val(replace_periods(e.second.first), 
                                                quote_string(e.second.second)));
    }
    allowed_field_value_stream.clear();
}

// parses the XML list of hash pairs (hash_type=hash_value) stored as a comma-delimited string
// in the event, and adds the hash_values to the map of allowed hash types.
// also adds them to the event_xml struct.
void XML_TO_ILF::parse_XML_hashes(stringstream &allowed_field_value_stream, 
                      map<string, pair<string, string>> &allowed_ecs_hashes_map, 
                      sysmon_xml *event_xml)
{  
    string hash_element;
    while(getline(allowed_field_value_stream, hash_element, ',')) {
        stringstream hash_element_stream(hash_element);
        string key, value;
        getline(hash_element_stream, key, '=');
        getline(hash_element_stream, value);
        ::transform(key.begin(), key.end(), key.begin(), ::tolower);
        try {
            allowed_ecs_hashes_map.at(key).second = value;
        } catch(...) { }
    };

    // only add subfields that are actually included in the XML event 
    // (i.e not the empty string in map)
    for (auto &e : allowed_ecs_hashes_map) {
        string hash_val = e.second.second;
        if (hash_val != "") {
            event_xml->event_data.push_back(key_val(replace_periods(e.second.first), 
                                                    quote_string(hash_val, true)));
        }
    }
    allowed_field_value_stream.clear();
}

// stores in a map all the allowed subfields that a single Sysmon field maps to from the config file,
// uses the subfield as the key and (full_ecs_field, "") as the value.
// e.g "md5" as the key and ("file.hash.md5", "") as the value
// e.g "name" as the key and ("user.name", "") as the value
void XML_TO_ILF::get_1_many_fields(map<string, pair<string, string>> *_map, string ecs_field_name)
{
    stringstream stream(ecs_field_name);

    string subfield;
    while(getline(stream, subfield, '.'));

    _map->insert({subfield, make_pair(ecs_field_name, "")});
}

// retrieves and stores all the event data from a given XML event into a given map
// Example of a data node: <Data Name='ProcessGuid'>{cc8aad4b-7121-654d-9a09-000000000a00}</Data>
void XML_TO_ILF::get_event_data(xml_node event, map<string, string> *_map)
{
    for (xml_node data_node : event.child("EventData").children()) {
        string field_name  = data_node.attribute("Name").value();
        string field_value = data_node.text().get();
        _map->insert({field_name, field_value});
    }
}

// Imports the three configuration JSON files provided by the user on the CLI:
// allowed fields JSON, field mappings JSON, and event names mapping JSON.
// Also reads in the redis configurations.
void XML_TO_ILF::import_configs()
{
    import_config(allowed_fields_base_path + allowed_fields_config_path, allowed_fields_json);
    import_config(field_mappings_base_path + field_mappings_config_path, field_mappings_json);
    import_config(event_names_base_path + event_names_config_path, event_names_json);
    import_config(redis_config_path, redis_json);
}

// Imports a configuration file at the given path and stores its contents in an empty JSON object 
// passed via reference. Program exits if there's an issue deserializing the file.
void XML_TO_ILF::import_config(string path, json &j)
{
    try {
        ifstream i(path);
        i >> j;
    } catch (const json::parse_error &e) {
        cerr << "Exception in import_config() with path: " << path << ". " << e.what() << endl;
        exit(EXIT_FAILURE);
    }
}

// replaces periods in the given event attribute keys with two underscores
string XML_TO_ILF::replace_periods(string key)
{
    return regex_replace(key, regex("[.]"), "__");
}

// retuns a quoted string if given string doesn't represent a number.
// handles the case where the value represents a hash that needs to be quoted.
string XML_TO_ILF::quote_string(string s, bool isHash /* = false */)
{
    if (isNumber(s) && !isHash)
        return s;
    
    ostringstream oss;
    oss << quoted(s);
    return oss.str();
}

// determines if a string represents a number (as decimal or hex) or not.
bool XML_TO_ILF::isNumber(const string& s)
{
    // hex
    if (s[0] == '0' && s[1] == 'x')
        return true;
    
    // decimal
    for (char const &ch : s) {
        if (!isdigit(ch) && ch != '.') 
            return false;
    }
    return true;
}

// wrapper for parsing all the command line arguments.
// verifies that all required arguments are provided.
// program exits if any are missing.
string XML_TO_ILF::parse_args(int argc, char *argv[])
{
    map<string, string> args;

    if ((argc - 1) % 2 != 0) {  // subtract one for the program name
        cerr << "Every argument flag must have an associated value. Argument count: " << argc << endl;
        exit(EXIT_FAILURE);
    }
    
    for (int i = 1; i < argc; i += 2) 
    {
        args[argv[i]] = argv[i + 1];
    }
    
    allowed_fields_config_path = args.count("-f") ? args["-f"] : allowed_fields_config_path;
    field_mappings_config_path = args.count("-m") ? args["-m"] : field_mappings_config_path;
    event_names_config_path = args.count("-e") ? args["-e"] : event_names_config_path;
    sleep_duration = args.count("-s") ? stoi(args["-s"]) : sleep_duration;
    xml_logs_path = args.count("-l") ? args["-l"] : xml_logs_path;

    return xml_logs_path;
}

json XML_TO_ILF::get_allowed_fields_json() const 
{
    return allowed_fields_json;
}

json XML_TO_ILF::get_field_mappings_json() const
{
    return field_mappings_json;
}

json XML_TO_ILF::get_event_names_json() const
{
    return  event_names_json;
}