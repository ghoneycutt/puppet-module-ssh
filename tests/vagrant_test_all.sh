#!/bin/bash -e

systems=$(vagrant status |grep virtualbox | awk '{print $1}')
echo -e "\nsystems to test:"
echo -e "================"
echo -e "\n${systems}"

for i in $systems
do
  echo -e "\n\n\n========= Running: vagrant up ${i}"
  vagrant up $i
  echo -e "\n\n\n========= Testing ssh to ${i}"
  vagrant ssh $i -c "exit"
  echo -e "\n\n\n========= Running: vagrant destroy -f ${i}"
  vagrant destroy -f $i
done
