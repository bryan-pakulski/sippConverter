#!/usr/bin/python3

import argparse
from sipp.parser import SIP_Parser


def main():
    parser = argparse.ArgumentParser(
        description="Convert pcap file to xml for SIPp")

    parser.add_argument("-i", "--input_file",
                        help="path to pcap input file", required=True)
    parser.add_argument("-c", "--client",
                        help="IP address of the A Party Caller", required=True)
    parser.add_argument("-s", "--server",
                        help="IP address of the B Party Caller", required=True)
    parser.add_argument("-a", "--a_number", help="A number (optional)",
                        default="999912344321")
    parser.add_argument("-b", "--b_number", help="B number (optional)",
                        default="888812344321")
    parser.add_argument("-n", "--scen_name", help="SIPp scenario name (optional)",
                        default="SIPp Scenario")
    parser.add_argument("-p", "--proxy", help="Flag to enable proxy support in generated XML, for use with kamailio or some other SIP proxy in between A/B parties",
                        default=False, action="store_true")
    args = parser.parse_args()

    # Load and parse pcap file
    parser = SIP_Parser(args.client, args.server, args.proxy)
    parser.load_pcap_as_dict(args.input_file)
    parser.save_pcap_to_xml(args.a_number, args.b_number,
                            args.scen_name)


if __name__ == "__main__":
    main()
