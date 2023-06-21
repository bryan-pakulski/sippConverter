## Python Requirements:

- python3
- pyshark
- xmlformatter

## Usage:

Open your pcap file in wireshark or your sip explorer of choice and identify which addresses you would like to use as your calling / terminating parties

Pass in the pcap / calling ip / terminating ip to the script, after generation is complete you should have a `UAC.xml` and `UAS.xml` file that you can use to generate call scenarios with.

```
./generateSIPp.py -i <capture.pcap> -c <A_party_ip> -s <B_party_ip>
```

## Options:

```
  -h, --help
  -i INPUT_FILE, --input_file INPUT_FILE
                        path to pcap input file
  -c CLIENT, --client CLIENT
                        IP address of the A Party Caller
  -s SERVER, --server SERVER
                        IP address of the B Party Caller
  -a A_NUMBER, --a_number A_NUMBER
                        A number
  -b B_NUMBER, --b_number B_NUMBER
                        B number
  -n SCEN_NAME, --scen_name SCEN_NAME
                        SIPp scenario name
  -m ACTION_SET, --action_set ACTION_SET
                        Generative actions to use
```

## How it works:

This is a very naive script that attempts to deconstruct the sip messaging between the A / B party. It will parse the pcap file and categorise packets as SENT / RECEIVED (whilst stripping unecessary information) for each side of the call. It will also strip SDP's from the messaging and include them with the captured packet information.

The marked packets are converted to sipp xml using a lookup with definitions for SIP codes / methods & responses. This has a lot of assumptions around the signalling and uses a basic approach to construct the messages, this is where some manual effort may need to be involved to tweak the scenario to work exactly as you want.

There is also some basic extendability with creating a custom actions class that can extract variables as needed for specific scenarios. There is a basic one included for a test set up that would include a kamailio and a softswitch between the A / B party.

## Generative Actions:

One of the strengths of SIPp is the ability to parse messages and construct responses based on regex expressions / variables etc..

This is somewhat captured in this application with the use of "ACTION_SETS" these are defined in `sipp_actions.py` and contain the regex expression as you would include it within a SIPp scenario.

The action set to use for a particular capture can be defined with the `-m / --action_set` flag when calling the script. Currently these allow the dynamic generation of VIA / Record-Route headers to support multi-hop calls.

The following actions are currently implemented.

```
==========
BASIC
==========

Captures information that you would use in a direct A -> B call with no intermediary

<action>
    <ereg regexp=".*" search_in="hdr" header="CSeq:"  assign_to="invite_cseq"/>
    <ereg regexp=".*" search_in="hdr" header="Via:" occurrence="1" assign_to="via_1"/>
    <assignstr assign_to="local_tag" value="[pid]-[call_number]" />
</action>

==========
BASIC_KAM
==========

Captures information that you would use in a A -> Kamailio Load Balancer -> B call
This also assumes a softswitch behind the kamailio to perform the actual routing

<action>
    <ereg regexp=".*" search_in="hdr" header="CSeq:"  assign_to="invite_cseq"/>
    <ereg regexp=".*" search_in="hdr" header="Via:" occurrence="1" assign_to="via_1"/>
    <ereg regexp=".*" search_in="hdr" header="Via:" occurrence="2" assign_to="via_2"/>
    <ereg regexp=".*" search_in="hdr" header="Record-Route:"  occurrence="1" assign_to="route_1"/>
    <assignstr assign_to="local_tag" value="[pid]-[call_number]" />
</action>

```

## Using with SIPp:

### A Party:

```
sipp -m 1 -sf UAC.xml -base_cseq 1111 -i <local_ip> -t u1 -s <called_number> <kamailio_ip_address> -p 5060
```

### B Party:

```
sipp --aa -base_cseq 1111 -i <local_ip> -sf UAS.xml -p 5060
```

## Validation:

The sipp scenario can be tested after generation using using the `test.sh` script. This will spin up two docker images based on the `docker-compose.yml` file.
The entrypoint scripts can be found in the `scripts` directory.

Note that this is a very simple direct call without any hops inbetween the two parties.

## Limitations:

- Only ipv4 / UDP scenarios supported for the time being
- SIP methods are very basic and require _massaging_ in order to get working
- Many SIP methods have been AI generated to save some time, so are most likely incorrect
