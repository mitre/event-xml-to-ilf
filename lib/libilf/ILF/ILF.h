//  Copyright (c) 2019-2021 The MITRE Corporation. ALL RIGHTS RESERVED.
//
//  The Happened-Before Language (HBL) and its detection engine are the
//  products of The MITRE Corporation, developed with MITRE funds.
//  This copyright notice must not be removed from this software, absent
//  MITRE's express written permission.

#ifndef ILF_H
#define ILF_H
#include <string>
#include <vector>

using namespace std;

struct key_val {
    string key;
    string value;

    key_val(string key, string val): key(key), value(val) {}
};

class ILF {
    private:
        string _eventType;
        string _sender;
        string _receiver;
        string _time;
        vector<key_val> _pairs;

    public:
        ILF();
        ILF(string eventType, string sender, string receiver, string time, vector<key_val> pairs);
        
        string to_string();
        string get_event();
        vector<key_val> get_key_vals();
        void set_key_vals(vector<key_val> new_vals);

};

#endif