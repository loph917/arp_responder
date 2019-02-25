## Aaron's ARP Responder
On my network I have a variety of Espressif ESP8266 modules running
firmware called Tasmota as well as my own home grown firmware implementations
of a thermostat and garage door controller written in C. The interface
is served directly from the ESP8266 using a combination of HTML, Javascript and
JQuery as well as using MQTT to talk to Home Assistant.

Due to what might be a bug in relation to the ESP8266 firwmare in the LwIP
protocol stack it appears that the ESP8266 will not respond to ARP queries
consistently. This has been discussd in the various ESP8266 forums with some
work arounds provided. Someone suggested a arp proxy for the ESP8266 devices
and provided a simple soluation based on scapy. Scapy is a bit heavy for this
and a better solution is pcapy which is a python interface to libpcap. Libpcap
is ubiquitous.


### REQUIREMENTS
	- python 3.5.3 (or better)
	- libpcap-dev (to install pcapy)
	- python-pcapy (python3 -m pip install pcapy)
	- requires sudo to run (due to promiscuous mode capture and raw packets)


### INSTALLATION
There are no strict installation requiments except what is noted above in
the requirements. You can simply place arp_responder.py and daemon.py in
a subdirectory of your choice.

systemd unit file:
```
	[Unit]
	Description=aaron's arp responder
	After=network-online.target

	[Service]
	User=root
	Type=simple
	ExecStart=/usr/bin/python3 /home/aaron/arp_responder/arp_responder.py -fg start
	ExecStop=/usr/bin/python3 /home/aaron/arp_responder/arp_responder.py -fg stop
	Restart=on-failure
	RestartSec=5s

	[Install]
	WantedBy=multi-user.target
```
  
### RUNNING
Prior to running, the mac_dict variable should be configured to indicate
which IP addresses arp_responder should send ARP replies for. The format of
mac_dict is a python dictionary. The key is the IP address and value is the
MAC address that will be in the ARP reply.

example:
```
	mac_dict = {"192.168.1.133" : "80:7D:3A:76:F4:B4",
        "192.168.1.135" : "84:0D:8E:96:0F:D5",
        "192.168.1.221" : "B4:E6:2D:23:C6:80",
        }
```

To start the responder:
```
	sudo ./arp_responder.py start
```

### OUTPUT EXAMPLES
```
aaron@raspberrypi:~/arp_responder$ sudo ./arp_responder.py status
arp_responder running (pid=7602)
```

```
aaron@raspberrypi:~/arp_responder$ sudo ./arp_responder.py help
usage: arp_responder.py [-h] [--pidfile PIDFILE] [--logfile LOGFILE] [-i INT]
                        [-s STAT_INTERVAL] [-fg] [-br]
                        {restart,start,stop,status,help}

aaron's arp responder (aar)

positional arguments:
  {restart,start,stop,status,help}

optional arguments:
  -h, --help            show this help message and exit
  --pidfile PIDFILE     pid file (default: /tmp/arp_responder.pid)
  --logfile LOGFILE     log file (default: arp_responder.log)
  -i INT, --int INT     interface to listen on (default: wlan0)
  -s STAT_INTERVAL, --stat-interval STAT_INTERVAL
                        statistics logging interval (default: 60)
  -fg, --foreground     run in the foreground (default: False)
  -br, --broadcast      broadcast arp responses (default: False)
```

```
aaron@raspberrypi:~/arp_responder$ tail arp_responder.log
2019-02-25 10:36:00 - arp_responder - INFO - arp_replies_in=20, arp_requests_in=19, arp_response_out=3, non_arp_pkts_in=1234, total_pkts_in=1273
2019-02-25 10:36:49 - arp_responder - INFO - 192.168.1.101 asked about 192.168.1.242, sending reponse
2019-02-25 10:36:50 - arp_responder - INFO - 192.168.1.101 asked about 192.168.1.221, sending reponse
2019-02-25 10:37:00 - arp_responder - INFO - arp_replies_in=33, arp_requests_in=34, arp_response_out=5, non_arp_pkts_in=1691, total_pkts_in=1758
```
