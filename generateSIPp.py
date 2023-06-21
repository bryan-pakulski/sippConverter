#!/usr/bin/python3

import sys
import pyshark
import asyncio

import sipp
import re
from sipp import UAC
from sipp import UAS

# Extract useful information from packet
def capturePacket(packet, category):
    sip_msg = {
    "direction": "",
    "src": "",
    "dst": "",
    "method": "",
    "header": "",
    "sdp": ""
    }

    if category == "UAC":
        if sipp.UAC_ip in packet.ip._all_fields["ip.src"]:
            sip_msg["direction"] = "SEND"
        elif sipp.UAC_ip in packet.ip._all_fields["ip.dst"]:
            sip_msg["direction"] = "RECV"
    elif category == "UAS":
        if sipp.UAS_ip in packet.ip._all_fields["ip.src"]:
            sip_msg["direction"] = "SEND"
        if sipp.UAS_ip in packet.ip._all_fields["ip.dst"]:
            sip_msg["direction"] = "RECV"

    sip_msg["src"] = packet.ip._all_fields["ip.src"]
    sip_msg["dst"] = packet.ip._all_fields["ip.dst"]

    # SDP extraction
    if "sip.Content-Type" in packet.sip._all_fields and packet.sip._all_fields["sip.Content-Type"] == "application/sdp":
        field_list=packet['sip']._all_fields
        field_list['sdp.media'] = field_list['sdp.media'].replace(field_list['sdp.media.port_string'], "[media_port]")
        sdp_str = "v=" + field_list['sip.msg_hdr'].split("v=")[1]

        ip_addr_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        sdp_str = re.sub(ip_addr_regex, "[local_ip]", sdp_str)
        sdp_str = re.sub("m=audio\s\d+", "m=audio [media_port]", sdp_str)
        sip_msg["sdp"] = "\n".join(sdp_str.split("\\xd\\xa"))
    else:
        sip_msg["sdp"] = ""
    
    # on situations where we don't use a sip.Method, we will get the status code i.e. 100 TRYING, 183 etc...
    if "sip.Method" not in packet.sip._all_fields:
        if sip_msg["direction"] == "SEND":
            sip_msg["method"] = packet.sip._all_fields["sip.Status-Line"]
        elif sip_msg["direction"] == "RECV":
            sip_msg["method"] = packet.sip._all_fields["sip.Status-Code"]
    else:
        sip_msg["method"] = packet.sip._all_fields["sip.Method"]

    sip_msg["header"] = "\n".join(packet.sip._all_fields["sip.msg_hdr"].split("\\xd\\xa"))
    print(category, sip_msg["direction"], sip_msg["method"], "from:", sip_msg["src"], "to:", sip_msg["dst"])

    return sip_msg

# Load the input pcap file and begin parsing
def load_SIP_pcap(input_file):
    print("UAC: ", sipp.UAC_ip)
    print("UAS: ", sipp.UAS_ip)

    sip_packets = {
        "UAC": [],
        "UAS": []
    }

    capture = pyshark.FileCapture(input_file)
    for packet in capture:
        try:
            if hasattr(packet, 'sip'):
                try:
                    category = None
                    if sipp.UAC_ip in packet.ip._all_fields["ip.src"] or sipp.UAC_ip in packet.ip._all_fields["ip.dst"]:
                        category = "UAC"
                        sip_packets[category].append(capturePacket(packet, category))
                    if sipp.UAS_ip in packet.ip._all_fields["ip.src"] or sipp.UAS_ip in packet.ip._all_fields["ip.dst"]:
                        category = "UAS"
                        sip_packets[category].append(capturePacket(packet, category))
                    
                    if category == None:
                        continue

                    
                except Exception as e:
                    print("Invalid SIP packet!", e)
        except OSError:
            pass
        except asyncio.TimeoutError:
            pass
    
    return sip_packets

# Create an XML scenario with the extracted information
def create_scenarios(sip_packets, scenario_name="SIPp Scenario"):
    caller = "999943214321"
    callee = "999912341234"
    scenario = scenario_name

    uac_writer = UAC.UAC(caller, scenario)
    uas_writer = UAS.UAS(callee, scenario)
    
    # UAC
    for entry in sip_packets["UAC"]:

        arguments = {
            "caller": caller,
            "callee": callee,
            "scenario_name": scenario,
            "subscriber": None,
            "event": None,
            "sdp": entry["sdp"]
        }
        
        if uac_writer.is_method(entry["method"]) and entry["direction"] == "SEND":
            uac_writer.send(entry["method"], arguments)

        elif uac_writer.is_method(entry["method"]) and entry["direction"] == "RECV":
            uac_writer.recv(entry["method"])

        elif entry["direction"] == "SEND":
            uac_writer.send_response(entry["method"], arguments)

        elif entry["direction"] == "RECV":
            uac_writer.recv_response(entry["method"])

    # UAS
    for entry in sip_packets["UAS"]:
        arguments = {
            "caller": caller,
            "callee": callee,
            "scenario_name": scenario,
            "subscriber": None,
            "event": None,
            "sdp": entry["sdp"]
        }
                
        if uas_writer.is_method(entry["method"]) and entry["direction"] == "SEND":
            uas_writer.send(entry["method"], arguments)

        elif uas_writer.is_method(entry["method"]) and entry["direction"] == "RECV":
            uas_writer.recv(entry["method"])

        elif entry["direction"] == "SEND":
            uas_writer.send_response(entry["method"], arguments)

        elif entry["direction"] == "RECV":
            uas_writer.recv_response(entry["method"])

    uac_writer.save("UAC.xml")
    uas_writer.save("UAS.xml")

# Main function
def main():
    # Check if argument is provided
    try:
        input_file = sys.argv[1]
        sipp.UAC_ip = sys.argv[2]
        sipp.UAS_ip = sys.argv[3]
    except IndexError:
        print("Usage: ./pcap2sipp.py <capture.pcap> <UAC_IP> <UAS_IP>")
        return
    
    # Load pcap file
    sip_packets = load_SIP_pcap(input_file)

    if len(sip_packets["UAC"]) == 0 or len(sip_packets["UAS"]) == 0:
        print("No SIP-enabled packets matching UAC or UAS found in capture!")
        return -1
        
    # Generate scenarios
    create_scenarios(sip_packets)
    
# Start program
if __name__=="__main__":
    main()