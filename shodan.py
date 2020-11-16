try:
    import sys
    import json
    import ipaddress
    import urllib.request
    import urllib.error
    from paepy.ChannelDefinition import CustomSensorResult  

    data = json.loads(sys.argv[1])
    host = data['host']
    apiKey = str(data['params'])

    url = 'https://api.shodan.io/shodan/host/{h}?key={k}'.format(h=host,k=apiKey)
    with urllib.request.urlopen(url) as res:
        raw = res.read()
    hostData = json.loads(raw.decode('ascii'))
    portsStr = " ".join([str(p) for p in hostData['ports']])
    msg = "Open Ports: " + portsStr
    sensor = CustomSensorResult(msg)
    sensor.add_channel('Open Ports',value=len(hostData['ports']),unit='ports')
    if 'vulns' in hostData.keys():
        sensor.add_channel('Vulnerabilities',value=len(hostData['vulns']),unit='vulns',is_limit_mode=True,limit_max_error=0)
    else:
        sensor.add_channel('Vulnerabilities',value=0,unit='vulns',is_limit_mode=True,limit_max_error=0)
except urllib.error.HTTPError as err:
    if err.code == 404:
        sensor = CustomSensorResult('No Data')
        sensor.add_channel('Open Ports',value=0,unit='ports')
        sensor.add_channel('Vulnerabilities',value=0,unit='vulns',is_limit_mode=True,limit_max_error=0)
except Exception as err:
    sensor = CustomSensorResult()
    sensor.add_error("Error - {0}".format(repr(err)))

print(sensor.get_json_result())


