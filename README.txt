----------------------
Command Line Arguments
----------------------
ids.java takes two comand line arguments. 
1: the file path of the policy file to be used 
2: the file path of the pcap file to be used


example: ... ids.java BlameAttack1.txt trace1.pcap

------
Output
------
If no packets are found that match the given policy, there will be no output. 
If a match is found, a warning will be printed to the console followed by the 
ip address of the potential attacker. 

example: WARNING!!! 192.168.1.100
