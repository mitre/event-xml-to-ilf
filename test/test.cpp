/*
    Copyright (c) 2023 The MITRE Corporation. 
    ALL RIGHTS RESERVED. This copyright notice must 
    not be removed from this software, absent MITRE's 
    express written permission.
*/

#include <assert.h>
#include <regex>

#include "../src/xml_translator.h"
/*
    Usage: 
        1) ./test
                to use the hardcoded files in ./input-logs/

        2) cat <file_name> | ./test
           e.g. cat ./input-logs/streaming.xml | ./test
                to use with a pipe

    Notes: 
        - Assumes that all configuration files are in the place specified in the XML_TO_ILF translator class (see 'base paths').
        - Input log files containing a single event must still be enclosed by an <Events></Events> tag.
        - The 1:many mappings case (for user and hashes) is handled in a separate function to account for the fact that not all
          allowed fields in the config are present in the XML events (e.g. sha1). It is ignored in all other test functions (test_configs()
          and test_values())
*/

string input_base_path = "./input-logs/";
string allowed_fields  = "allowed_fields.json";
string field_mappings  = "field_mappings.json";
string event_names     = "event_names.json";

void five_events_test();
void test_all_basics();
void test_configs(string id);
void test_values(string id);
void test_streaming_cin();
void test_streaming_filestream();
void one_to_many_mappings(string event_id);
void assert_key(vector<key_val> attributes, string keym, bool negate = false);
void assert_key_val(vector<key_val> attributes, string key, string value, bool negate = false);
void setup_event(string id, json &allowed_fields, json &event_names, json &field_mappings, string &xml_logs_path);

int main (int argc, char *argv[]) 
{

    // Goes through all the files in the './input_logs/' directory
    test_all_basics();
    five_events_test();

    for (int i = 1; i <= 27; i++) {
        if (i == 25 || i == 26) {
            cout << "Skipping " << i << endl;
            continue;
        }

        if (i == 27) i = 255;

        cout << "Event type " << i << endl;
        test_configs(to_string(i));
        test_values(to_string(i));
        cout << "* * * * " << endl;
    }

    one_to_many_mappings("1");

    // only use when a file and stream are provided on the CLI!
    // test_streaming_cin();

    test_streaming_filestream();

    cout << "All tests passed!" << endl;
    return 0;
}

// from cin
void test_streaming_cin()
{
    string s = "stdin";
    char *mock_cli[] = { (char *) "./main", 
                            (char *) "-m", 
                            (char *) field_mappings.c_str(), 
                            (char *) "-f", 
                            (char *) allowed_fields.c_str(), 
                            (char *) "-e", 
                            (char *) event_names.c_str(), 
                            (char *) "-l", 
                            (char *) s.c_str() };
    
    XML_TO_ILF translator = XML_TO_ILF(9, mock_cli);
    assert(translator.run_from_stdin(cin) == 0);
}

// from a filestream
void test_streaming_filestream()
{
    string s = "stdin";
    char *mock_cli[] = { (char *) "./main", 
                            (char *) "-m", 
                            (char *) field_mappings.c_str(), 
                            (char *) "-f", 
                            (char *) allowed_fields.c_str(), 
                            (char *) "-e", 
                            (char *) event_names.c_str(), 
                            (char *) "-l", 
                            (char *) s.c_str() };
    
    XML_TO_ILF translator = XML_TO_ILF(9, mock_cli);
   
    ifstream my_input_file;
    my_input_file.open("./input-logs/streaming.xml");
    
    assert(translator.run_from_stdin(my_input_file) == 0);
}

// Reads in the entirety of each configuration file into JSON objects,
// and extracts and stores the data relevant to the given event under test.
void setup_event(string id, json &sub_allowed_fields, json &sub_event_names, json &sub_field_mappings, string &xml_logs_path)
{
    json allowed_fields, field_mappings, event_names;
    
    ifstream i("../lib/sysmon_configurations/allowed-field-configs/allowed_fields.json");
    i >> allowed_fields;

    ifstream i2("../lib/sysmon_configurations/field-mappings-configs/field_mappings.json");
    i2 >> field_mappings;
    
    ifstream i3("../lib/sysmon_configurations/name-mappings-configs/event_names.json");
    i3 >> event_names;

    sub_allowed_fields = json::object({ { id, allowed_fields.at(id) }});
    sub_field_mappings = json::object({ { id, field_mappings.at(id) }});
    sub_event_names    = json::object({ { id, event_names.at(id) }});
    xml_logs_path      = input_base_path + id + ".xml";
}

// Tests that the configurations are properly followed by the translator for a given event type
void test_configs(string id)
{   
    // setup test
    json allowed_fields, event_names, field_mappings;
    string xml_logs_path;
    setup_event(id, allowed_fields, event_names, field_mappings, xml_logs_path);
    int num_allowed_fields = allowed_fields.at(id).size();

    // process event
    XML_TO_ILF t = XML_TO_ILF(allowed_fields, event_names, field_mappings, xml_logs_path, NULL);
    ILF *ilf = t.process_event(t.get_root()->child("Events").first_child());
    cout << ilf->to_string() << endl << endl;

    // test configs
    // verify that only the fields/field mappings listed in the JSON allowed_fields object 
    // are in the ILF attributes plus the event_code
    vector<key_val> attributes = ilf->get_key_vals();

    // NOTE: since we ignore the 1:many mappings, can't do a size check
    // +1 accounts for the added "event__code" field
    // cerr << (int)attributes.size() << ", " << num_allowed_fields + 1 << endl;
    // assert((int)attributes.size() == num_allowed_fields + 1);

    // verify that the allowed mapped fields are in the ILF attributes list
    for (string e : allowed_fields.at(id)) {
        // skip 1:many mappings here as there are edge cases (e.g. sha1 is allowed but not present in events)
        auto mapped_field = field_mappings.at(id).at(e);
        if (mapped_field.is_array()) {
            continue;
        }
        assert_key(attributes, XML_TO_ILF::replace_periods(mapped_field));
    }
}

// Test that the values in the XML event appear correctly in the ILF for a given event type
void test_values(string id)
{
    // setup test
    json allowed_fields, event_names, field_mappings;
    string xml_logs_path;

    setup_event(id, allowed_fields, event_names, field_mappings, xml_logs_path);

    // process event
    XML_TO_ILF t = XML_TO_ILF(allowed_fields, event_names, field_mappings, xml_logs_path, NULL);
    ILF *ilf = t.process_event(t.get_root()->child("Events").first_child());
    vector<key_val> attributes = ilf->get_key_vals();

    // test values: parse the XML event, grab values, do the mapping to ECS
    xml_document root;
    if (!root.load_file(xml_logs_path.c_str())) {
        cerr << "Error opening the event log file at " << xml_logs_path << endl;
        exit(EXIT_FAILURE);
    }

    xml_node event = root.child("Events").first_child();
    // cout << "\n\n* * * * Raw event XML * * * *"<< endl;
    // event.print(cout, "", format_raw);

    // find the value for the allowed field in the xml
    // compare it to the value in the ILF keyed by the mapped ECS field
    for (string allowed_field : allowed_fields.at(id)){
        for (xml_node data_node : event.child("EventData").children()) {
            if (data_node.attribute("Name").value() == allowed_field) {
                string xml_value = data_node.text().get();
                auto ecs_field = field_mappings.at(id)[allowed_field];
                if (ecs_field.is_array()) {
                    continue;
                }
                assert_key_val(attributes, XML_TO_ILF::replace_periods(ecs_field), xml_value);
            }
        }
    }
}

// TODO handle cases 25, 26
// Tests the constructor that uses command line arguments with real configuration JSON files
// Tests that event codes are properly included in the ILF string
void test_all_basics()
{
    cout << "test_all_basics()" << endl << endl;
    // loop through all the input files named "i.xml" where i in {1..26}
    for (int i = 1; i <= 27; i++) {

        // currently missing examples for these two Sysmon event types
        if (i == 26  || i == 25)
            continue;
        if (i == 27)
            i = 255;
        
        string s = input_base_path + to_string(i) + ".xml";

        char *mock_cli[] = { (char *) "./main", 
                             (char *) "-m", 
                             (char *) field_mappings.c_str(), 
                             (char *) "-f", 
                             (char *) allowed_fields.c_str(), 
                             (char *) "-e", 
                             (char *) event_names.c_str(), 
                             (char *) "-l", 
                             (char *) s.c_str() };

        XML_TO_ILF translator = XML_TO_ILF(9, mock_cli);

        // Since there's only one event in the test file, it's the first child node.
        xml_node event = translator.get_root()->child("Events").first_child();
        ILF *ilf = translator.process_event(event);
        assert(ilf != NULL);
        
        string event_code_attr = "event__code", expected_code = to_string(i);
        vector<key_val> attributes = ilf->get_key_vals();
        assert(!attributes.empty());

        // check the presence and correctness of the event_code attribute in the ILF string
        assert_key_val(attributes, event_code_attr, expected_code);
    }
}

// Checks that all 5 events in the XML file are processed
void five_events_test()
{   
    cout << "five_events_test()" << endl << endl;
    string s = "./input-logs/five_events.xml";

    char *mock_cli[] = { (char *) "./main", 
                            (char *) "-m", 
                            (char *) field_mappings.c_str(), 
                            (char *) "-f", 
                            (char *) allowed_fields.c_str(), 
                            (char *) "-e", 
                            (char *) event_names.c_str(), 
                            (char *) "-l", 
                            (char *) s.c_str() };
    
    XML_TO_ILF translator = XML_TO_ILF(9, mock_cli);
    assert(translator.run() == 0);
    assert(translator.get_num_events_processed() == 5);
}

// asserts that a given key does or does not exist in the ILF's list of attributes.
void assert_key(vector<key_val> attributes, string key, bool negate /*= false*/)
{   
    auto it = find_if(attributes.begin(), 
                      attributes.end(), 
                      [&key](const key_val& obj) { 
                          return obj.key == key; 
                      });
    if (negate)
        assert(it == attributes.end());
    else
        assert(it != attributes.end());
}

// asserts that a given key/value pair does or does not exist in the ILF's list of attributes.
// Note: for simplicity, this function removes quotes if they exist and just checks the contents.
void assert_key_val(vector<key_val> attributes, string key, string value, bool negate /*= false*/)
{
    auto it = find_if(attributes.begin(), 
                      attributes.end(), 
                      [&key, &value](const key_val& obj) 
                      { 
                        // take in the already quoted string
                        stringstream in;
                        in << obj.value;

                        // remove its quotes and store in new string
                        string out;
                        in >> quoted(out);         
                        return obj.key == key &&  out == value; 
                      });

    if (negate)
        assert(it == attributes.end());
    else
        assert(it != attributes.end());
}

// Tests the 1:many mappings case using the event #1.
// <Data Name="Hashes">MD5=D8CD7DEE9C56A21591096E9500B52208,
//                    SHA256=3640AA594D0FEA820310996FF56BFA6B80F3885A942B80A9D02A56E35C438458,
//                    IMPHASH=527C7C66CDD13D72D793BCA3A417BCBE
//</Data>
void one_to_many_mappings(string event_id)
{    
    string xml_logs_path;
    json allowed_fields, event_names, field_mappings;
    setup_event(event_id, allowed_fields, event_names, field_mappings, xml_logs_path);

    XML_TO_ILF t   = XML_TO_ILF(allowed_fields, event_names, field_mappings, xml_logs_path, NULL);
    xml_node event = t.get_root()->child("Events").first_child();
    ILF *ilf       = t.process_event(event);
    cout << ilf->to_string() << endl;

    vector<key_val> attributes = ilf->get_key_vals();

    // User field
    assert_key(attributes, "user__domain");
    assert_key_val(attributes, "user__domain", "DESKTOP-R35QU0N");

    assert_key(attributes, "user__name");
    assert_key_val(attributes, "user__name", "root");
    
    // Hashes field
    string md5     = "process__hash__md5", 
           sha256  = "process__hash__sha256", 
           imphash = "process__pe__imphash";

    assert_key(attributes, md5);
    assert_key_val(attributes, md5, "D8CD7DEE9C56A21591096E9500B52208" );
    
    assert_key(attributes, sha256);
    assert_key_val(attributes, sha256, "3640AA594D0FEA820310996FF56BFA6B80F3885A942B80A9D02A56E35C438458" );
    
    assert_key(attributes, imphash);
    assert_key_val(attributes, imphash, "527C7C66CDD13D72D793BCA3A417BCBE" );

    // the event does not contain an entry for sha1, so assert that it's not in the ILF.
    bool negate = true;
    assert_key(attributes, "process__hash__sha1", negate);
}