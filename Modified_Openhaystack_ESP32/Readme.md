This contains the modifed code of openhaystack for a custom airtag. This can continuously change the MAC address and thus can't be detected by current tracking methods.

keygen_maybe.py is the python script to generate the keys.

python ./keygen_maybe.py -n x 


We can then flash it using the following command

./flash_esp32.sh -p /dev/ttyACM0 -k keys.txt


Currently supports 50,000 keys but can be increased. These keys will be sufficient to transmit a different key for an entire day and was currently enough for out advanced attacker.

