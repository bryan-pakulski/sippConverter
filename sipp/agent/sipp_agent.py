import sipp.agent
from sipp.sip_methods import Methods
from sipp.sipp_actions import Actions

import xmlformatter

# This agent class works to convert the dictionary information passed from the parser into XML that SIPP can understand


class SIPP_Agent:

    # SIP messsages we will record route on
    RRS_CODES = [
        "183",
        "180",
        "INVITE"
    ]

    # XML Tag to record route
    RECORD_ROUTE = "rrs=\"true\""

    def __init__(self, number, scenario_name, action_set):

        self.number = number
        self.scenario_name = scenario_name

        # SIPP Scenario container
        self.scenario = []

        # XML Generators
        self.sip_actions = Actions(action_set)
        self.sip_methods = Methods()

        self.have_saved_routes = False
        self.message_counter = 0
        self.use_actions = False

    def add_scenario(self, content):
        self.scenario.append(content)

    # Keep track of our method increments, useful for responding to correct branch
    def increment(self):
        self.message_counter += 1

    def get_counter(self):
        return self.message_counter

    # Check if we have a sip_method function defined for this method
    def is_method(self, method):
        return method in self.sip_methods.call

    # Determine if we should use Record-Route for a given response code
    def use_rrs(self, response_code):

        for code in self.RRS_CODES:
            if (code in response_code):
                self.have_saved_routes = True

        # TODO: in the apply class make it so that actions can be defined per method i.e. lookup table
        # We want to apply actions on our invite
        if "INVITE" in response_code:
            self.use_actions = True

        return self.have_saved_routes

    def send(self, method, arguments):
        if (self.have_saved_routes):
            arguments["routes"] = "[routes]"

        self.add_scenario(f"""
        <send>
            {self.sip_methods.call[method](self, arguments)}
        </send>
        """)
        self.increment()

    def recv(self, method):
        self.add_scenario(f"""
        <recv request="{method}" {self.RECORD_ROUTE if self.use_rrs(method) else ""}>
        {self.sip_actions.xml() if self.use_rrs(method) else ""}
        </recv>
        """)
        self.increment()

    def recv_response(self, response_code, optional="false"):
        self.add_scenario(f"""
        <recv response="{response_code}" {self.RECORD_ROUTE if self.use_rrs(response_code) else ""}
            optional="{optional}">
        </recv>
        """)
        self.increment()

    def send_response(self, status_line, arguments):
        self.add_scenario(f"""
        <send>
            <![CDATA[
                {status_line}
                {self.sip_actions.get_via() if self.sip_actions.use_via(status_line) else "[last_Via:]"}
                [last_From:]
                [last_To:];{"tag=[$local_tag]" if self.use_actions else "tag=[call_number]"}
                {self.sip_actions.get_routes() if "200" not in status_line else "[routes]"}
                [last_Call-ID:]
                {"CSeq: [$invite_cseq]" if self.use_actions and "200" in status_line else "[last_CSeq:]"}
                Contact: <sip:[local_ip]:[local_port];transport=[transport]>
                {"Content-Type: application/sdp" if arguments["sdp"] != "" else ""}
                Content-Length: [len]
                
                {arguments["sdp"]}
            ]]>
        </send>
        """)
        self.increment()

    def wait(self, time_ms):
        self.add_scenario(f"""
        <pause milliseconds="{time_ms}"/>
        """)

    # Parse a line and format if required
    def parse_scenario(self, scen):
        CDATA = False
        INDENTATION = 4

        current_indentation = 0
        output = ""
        pre_sdp = True
        sdp_start = 0
        index = -1

        for line in scen.splitlines():
            index += 1

            if "<![CDATA[" in line:
                CDATA = True
                current_indentation = len(line) - len(line.lstrip())
                output += '\n' + (' ' * current_indentation + line.lstrip())
            elif CDATA and "]]>" in line:
                CDATA = False
                output += '\n' + (' ' * current_indentation + line.lstrip())
            elif CDATA:
                # Log where sdp starts so we can strip extra whitespace
                if "Content-Length: [len]" in line:
                    pre_sdp = False
                    sdp_start = index + 1

                # Strip empty lines pre sdp
                if pre_sdp and (line.isspace() or len(line.lstrip()) == 0):
                    continue
                # Strip empty lines after sdp starts
                elif index > sdp_start and (line.isspace() or len(line.lstrip()) == 0):
                    continue
                else:
                    output += '\n' + \
                        (' ' * (current_indentation + INDENTATION) + line.lstrip())
            else:
                output += '\n' + (line.lstrip())

        return output

    def save(self, outfile):
        xml_header = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n\n"
        header = f"<scenario name=\"{self.scenario_name}\">"
        header_close = "\n</scenario>"

        output_string = ""
        output_string += xml_header
        output_string += header
        # Write each scenario action
        for action in self.scenario:
            output_string += self.parse_scenario(action)
        output_string += header_close
        formatter = xmlformatter.Formatter(indent="4", correct=True)

        with open(outfile, 'w') as output:
            output.write(formatter.format_string(output_string).decode())
