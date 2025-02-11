//  Copyright (c) 2019-2021 The MITRE Corporation. ALL RIGHTS RESERVED.
//
//  The Happened-Before Language (HBL) and its detection engine are the
//  products of The MITRE Corporation, developed with MITRE funds.
//  This copyright notice must not be removed from this software, absent
//  MITRE's express written permission.

#include "ILF.h"

ILF::ILF() {
    _eventType = "";
    _sender = "";
    _receiver = "";
    _time = "";
    _pairs = vector<key_val>();
}

ILF::ILF(string eventType, string sender, string receiver, string time, vector<key_val> pairs) {
    _eventType = eventType;
    _sender = sender;
    _receiver = receiver;
    _time = time;
    _pairs = pairs;
}

string ILF::to_string()
{
    string s = "";
    if(_pairs.size() > 0)
    {
        for (unsigned int i = 0; i < _pairs.size(); i++)
        {
            s += _pairs[i].key + "=" + _pairs[i].value + ";";
        }
        s.pop_back();
    }
    return _eventType + "[" + _sender + "," + _receiver + "," + _time + ",(" + s + ")] "; 
}

string ILF::get_event()
{
    return _eventType;
}

vector<key_val> ILF::get_key_vals()
{
    return _pairs;
}

void ILF::set_key_vals(vector<key_val> new_vals){
    //_pairs = new_vals; // this might only make an alias...

    _pairs.clear();
    for(long unsigned int i = 0; i < new_vals.size(); i++){
        _pairs.push_back(new_vals[i]);
    }
}