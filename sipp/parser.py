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

    def __init__(self, client_addr, server_addr):
        self.uac_ip = client_addr
        self.uas_ip = server_addr
        self.pcap_dict = {
            agent.CLIENT: [],
            agent.SERVER: []
        }

    # Extract useful information from packet
    def __parse_packet(self, packet, address):
        msg = message()

        # Get direction of packet
        if address in packet.ip._all_fields["ip.src"]:
            msg.direction = DIR.SEND
        elif address in packet.ip._all_fields["ip.dst"]:
            msg.direction = DIR.RECV

        # Get source and destination
        msg.src = packet.ip._all_fields["ip.src"]
        msg.dst = packet.ip._all_fields["ip.dst"]

        # Extract SDP from packet
        if "sip.Content-Type" in packet.sip._all_fields and packet.sip._all_fields["sip.Content-Type"] == "application/sdp":
            field_list = packet['sip']._all_fields

            # Replace media fields and ip addresses with sipp friendly variables
            field_list['sdp.media'] = field_list['sdp.media'].replace(
                field_list['sdp.media.port_string'], "[media_port]")
            sdp_str = "v=" + field_list['sip.msg_hdr'].split("v=")[1]

            ip_addr_regex = re.compile(
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            sdp_str = re.sub(ip_addr_regex, "[local_ip]", sdp_str)
            sdp_str = re.sub(
                "m=audio\s\d+", "m=audio [media_port]", sdp_str)
            print(sdp_str.split("\\xd\\xa"))
            msg.sdp = "\n".join(sdp_str.split("\\xd\\xa"))

        # On situations where we don't use a sip.Method, we will get the status code i.e. 100 TRYING, 183 etc...
        if "sip.Method" not in packet.sip._all_fields:
            if msg.direction == DIR.SEND:
                msg.method = packet.sip._all_fields["sip.Status-Line"]
            elif msg.direction == DIR.RECV:
                msg.method = packet.sip._all_fields["sip.Status-Code"]
        else:
            msg.method = packet.sip._all_fields["sip.Method"]

        # Extract header
        msg.header = "\n".join(
            packet.sip._all_fields["sip.msg_hdr"].split("\\xd\\xa"))

        if (not msg.validate()):
            raise ValueError("failed to validate!", msg.as_string())

        print(f"{msg.method}{'(SDP)' if msg.sdp != '' else ''} {msg.direction} from: {msg.src} to: {msg.dst}")
        return msg

    # Load the input pcap file and parse into a dictionary of key elements (see __message class)
    def load_pcap_as_dict(self, input_file):
        print(f"{agent.CLIENT}: ", self.uac_ip)
        print(f"{agent.SERVER}: ", self.uas_ip)

        capture = pyshark.FileCapture(input_file)
        for packet in capture:
            try:
                if hasattr(packet, 'sip'):
                    try:
                        # Capture A party packets
                        if self.uac_ip in packet.ip._all_fields["ip.src"] or self.uac_ip in packet.ip._all_fields["ip.dst"]:
                            self.pcap_dict[agent.CLIENT].append(
                                self.__parse_packet(packet, self.uac_ip))

                        # Capture B party packets
                        if self.uas_ip in packet.ip._all_fields["ip.src"] or self.uas_ip in packet.ip._all_fields["ip.dst"]:
                            self.pcap_dict[agent.SERVER].append(
                                self.__parse_packet(packet, self.uas_ip))

                    except Exception as e:
                        print("Invalid SIP packet!", e)
            except OSError:
                pass

        if len(self.pcap_dict[agent.CLIENT]) == 0 or len(self.pcap_dict[agent.SERVER]) == 0:
            raise Exception(
                f"No SIP-enabled packets matching {self.uac_ip} or {self.uas_ip} found in capture!")
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
    def save_pcap_to_xml(self, scenario_name, a_party, b_party, action_set):

        if self.pcap_dict == None:
            raise Exception(
                "No pcap dictionary loaded! has load_pcap_as_dict been called?")

        uac_writer = sipp_agent.SIPP_Agent(a_party, scenario_name, action_set)
        uas_writer = sipp_agent.SIPP_Agent(b_party, scenario_name, action_set)

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
