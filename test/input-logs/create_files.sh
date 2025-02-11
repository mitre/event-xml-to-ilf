#!/bin/bash

for i in {255..255}
do
    xmllint --format ${i}.xml > ${i}_new.xml
    mv ${i}_new.xml ${i}.xml
done