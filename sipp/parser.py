import pyshark

import sipp.agent as agent
from sipp.agent import sipp_agent

from enum import Enum
import os
import re


# Message object wrapper
class message:
    def __init__(self):
        self.direction = None
        self.src = None
        self.dst = None
        self.method = None
        self.header = None
        self.sdp = ""

    # Basic validation
    # We require everything except for an SDP
    def validate(self):
        if (self.direction == None):
            return False
        if (self.src == None):
            return False
        if (self.dst == None):
            return False
        if (self.method == None):
            return False
        return True

    def as_string(self):
        return (
            f"""
        direction:   {self.direction}
        source:      {self.src}
        destination: {self.dst}
        sip method:  {self.method}
        sip header:  {self.header}
        sip sdp:     {self.sdp}
        """)


class DIR(Enum):
    SEND = "SEND"
    RECV = "RECV"


class SIP_Parser:

    OUTPUT_DIRECTORY = "scenarios"

    def __init__(self, client_addr, server_addr, proxy):
        self.uac_ip = client_addr
        self.uas_ip = server_addr
        self.pcap_dict = {
            agent.CLIENT: [],
            agent.SERVER: []
        }
        self.proxy = proxy

    # Extract useful information from packet
    def __parse_packet(self, packet, ip_layer, address):
        msg = message()

        # Get direction of packet
        if address in ip_layer._all_fields["ip.src"]:
            msg.direction = DIR.SEND
        elif address in ip_layer._all_fields["ip.dst"]:
            msg.direction = DIR.RECV

        # Get source and destination
        msg.src = ip_layer._all_fields["ip.src"]
        msg.dst = ip_layer._all_fields["ip.dst"]
        
        # Extract SDP / headers
        try:
            headers_dict = {}
            
            # Extract all fields from the SIP layer
            for field_name in packet.sip.firld_names:
                # Skip internal/special fields
                if field_name.startswith("_"):
                    continue

                field_value = getattr(packet.sip, field_name)
                header_name = field_name.replace("sip.", "")
                headers_dict[header_name] = field_value

            msg.header = headers_dict
        except Exception as e:
            print("Failed in retrieving headers!", e)

        try:
            if "sip.Content-Type" in packet.sip._all_fields and packet.sip._all_fields["sip.Content-Type"] == "application/sdp":
                # Replace media fields and ip addresses with sipp friendly variables
                hex_sdp_str = packet.sip.msg_body.__str__().replace(":", '')
                sdp_str = bytes.fromhex(hex_sdp_str).decode('ascii')


                ip_addr_regex = re.compile(
                    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
                sdp_str = re.sub(ip_addr_regex, "[local_ip]", sdp_str)
                sdp_str = re.sub("m=audio\\s\\d+", "m=audio [media_port]", sdp_str)
                msg.sdp = sdp_str.replace("\\xd\\xa", '\n')

                # Format SDP if required, newer versions of python seem to concatenate SDP on a single line
                sdp_pattern = r'\s(\w+)='
                msg.sdp = re.sub(sdp_pattern, '\\n\\g<1>=', msg.sdp)
        except Exception as e:
            print("Failed in retrieving SDP!", e)
            msg.sdp = ""


        # On situations where we don't use a sip.Method, we will get the status code i.e. 100 TRYING, 183 etc...
        if "sip.Method" not in packet.sip._all_fields:
            if msg.direction == DIR.SEND:
                msg.method = packet.sip._all_fields["sip.Status-Line"]
            elif msg.direction == DIR.RECV:
                msg.method = packet.sip._all_fields["sip.Status-Code"]
        else:
            msg.method = packet.sip._all_fields["sip.Method"]

        if (not msg.validate()):
            raise ValueError("failed to validate!", msg.as_string())

        print(f"{msg.method}{'(SDP)' if msg.sdp != '' else ''} {msg.direction} from: {msg.src} to: {msg.dst}")
        return msg

    # Load the input pcap file and parse into a dictionary of key elements (see __message class)
    def load_pcap_as_dict(self, input_file):
        print(f"{agent.CLIENT}: ", self.uac_ip)
        print(f"{agent.SERVER}: ", self.uas_ip)

        capture = pyshark.FileCapture(input_file, display_filter="sip")
        for packet in capture:
            try:
                if hasattr(packet, "sip"):
                    # We can have multiple ip layers...
                    for ip_layer in packet.get_multiple_layers('ip'):
                        #try:
                        # Capture A party packets
                        if self.uac_ip in ip_layer._all_fields["ip.src"] or self.uac_ip in ip_layer._all_fields["ip.dst"]:
                            self.pcap_dict[agent.CLIENT].append(
                                self.__parse_packet(packet, ip_layer, self.uac_ip))

                        # Capture B party packets
                        if self.uas_ip in ip_layer._all_fields["ip.src"] or self.uas_ip in ip_layer._all_fields["ip.dst"]:
                            self.pcap_dict[agent.SERVER].append(
                                self.__parse_packet(packet, ip_layer, self.uas_ip))

                        #except Exception as e:
                        #    print("Invalid SIP packet layer!", e)
            except OSError:
                pass
            
        err = ""
        if len(self.pcap_dict[agent.CLIENT]) == 0:
            err += f"{self.uac_ip}"
        if len(self.pcap_dict[agent.SERVER]) == 0:
            err += f" {self.uas_ip}"

        if (err != ""):
            raise Exception(
                f"No SIP-enabled packets matching {err} found in capture!")
        else:
            print(
                f"Captured {len(self.pcap_dict[agent.CLIENT])} UAC packets & {len(self.pcap_dict[agent.SERVER])} UAS packets")

    def __send_to_writer(self, writer, data_dict, a_party, b_party, scenario_name):
        # For each entry determine if we need to add additional information i.e. sdp
        for scenario in data_dict:

            # This argument list is passed to sip_methods so that the CDATA string can be built with additional information
            arguments = {
                "caller": a_party,
                "callee": b_party,
                "scenario_name": scenario_name,
                "routes": "",
                "subscriber": None,
                "event": None,
                "sdp": scenario.sdp
            }

            # Check if we are dealing with a SIP method i.e. INVITE / ACK / BYE etc..
            if writer.is_method(scenario.method):
                if scenario.direction == DIR.SEND:
                    writer.send(scenario.method, arguments)
                if scenario.direction == DIR.RECV:
                    writer.recv(scenario.method)

            # We are dealing with a non method response i.e. 180 / 183
            elif scenario.direction == DIR.SEND:
                writer.send_response(scenario.method, arguments)
            elif scenario.direction == DIR.RECV:
                writer.recv_response(scenario.method)

    # Create SIPP XML scenarios with the extracted dictionary
    def save_pcap_to_xml(self, a_party, b_party, scenario_name):

        if self.pcap_dict == None:
            raise Exception(
                "No pcap dictionary loaded! has load_pcap_as_dict been called?")

        uac_writer = sipp_agent.SIPP_Agent(a_party, scenario_name, self.proxy, True)
        uas_writer = sipp_agent.SIPP_Agent(b_party, scenario_name, self.proxy, False)

        # Determine the type of each packet for SIPP i.e. send / recv / response
        self.__send_to_writer(
            uac_writer, self.pcap_dict[agent.CLIENT], a_party, b_party, scenario_name)
        self.__send_to_writer(
            uas_writer, self.pcap_dict[agent.SERVER], a_party, b_party, scenario_name)

        # check whether directory already exists
        if not os.path.exists(self.OUTPUT_DIRECTORY):
            os.mkdir(self.OUTPUT_DIRECTORY)
            print(f"Folder created! {self.OUTPUT_DIRECTORY}")

        uac_writer.save(f"{self.OUTPUT_DIRECTORY}/UAC.xml")
        uas_writer.save(f"{self.OUTPUT_DIRECTORY}/UAS.xml")
