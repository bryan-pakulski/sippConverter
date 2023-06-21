## Python Requirements:
- python3
- pyshark
- xmlformatter

## Usage:
Open your pcap file in wireshark or your sip explorer of choice and identify which addresses you would like to use as your calling / terminating parties

Pass in the pcap / calling ip / terminating ip to the script, after generation is complete you should have a `UAC.xml` and `UAS.xml` file that you can use to generate call scenarios with.
```
./generateSIPp.py <capture.pcap> <A_party_ip> <B_party_ip> 
```

## How it works:
This is a very naive script that attempts to deconstruct the sip messaging between the A / B party. It will parse the pcap file and categorise packets as SENT / RECEIVED (whilst stripping unecessary information) for each side of the call. It will also strip SDP's from the messaging and include them with the captured packet information.

The marked packets are converted to sipp xml using a lookup with definitions for SIP codes / methods & responses. This has a lot of assumptions around the signalling and uses a basic approach to construct the messages, this is where some manual effort may need to be involved to tweak the scenario to work exactly as you want.

There is also some basic extendability with creating a custom actions class that can extract variables as needed for specific scenarios. There is a basic one included for a test set up that would include a kamailio and a softswitch between the A / B party.

## Using with SIPp:

### A Party:
```
sipp --aa -base_cseq 1111 -i <local_ip> -sf UAS.xml -p 5060
```

### B Party:
```
sipp -m 1 -sf UAC.xml -base_cseq 1111 -i <local_ip> -t u1 -s <called_number> <kamailio_ip_address> -p 5060
```

## Limitations:
- Only ipv4 / UDP scenarios supported for the time being
- SIP methods are very basic and require *massaging* in order to get working
- Many SIP methods have been AI generated to save some time, so are most likely incorrect
