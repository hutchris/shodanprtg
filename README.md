# shodanprtg
PRTG sensor that monitors Shodan API for open ports and vulnerabilities

For devices being monitored in PRTG that have a public IP address, you can track the number of open ports and vulnerabilities that are detected by Shodan.

Paste the shodan.py file into the custom sensors directory on the PRTG machine that will be doing the query. If you have remote probes, it will have to be on those machines. The custom sensor directory is found here: C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\python

Add this as a "python script advanced" sensor and pick the shodan.py file from the drop down. Put your shodan API key in the Additional Parameters field.

You should then see the results show up in PRTG. You should set appropriate warning and error limits on the channels that you want to be alerted about.
