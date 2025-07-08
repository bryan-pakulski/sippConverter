import sipp.agent
from sipp.sip_methods import Methods

import xmlformatter

# This agent class works to convert the dictionary information passed from the parser into XML that SIPP can understand
class SIPP_Agent:
    def __init__(self, number, scenario_name, proxy, is_uac):

        self.number = number
        self.scenario_name = scenario_name

        # SIPP Scenario container
        self.scenario = []

        # XML Generators
        self.sip_methods = Methods()

        self.message_counter = 0

        self.proxy = proxy
        self.first_invite = True
        self.is_uas = not is_uac

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

    def send(self, method, arguments):
        arguments["proxy"] = self.proxy
        self.add_scenario(f"""
        <send>
            {self.sip_methods.call[method](self, arguments)}
        </send>
        """)
    
        # UAS will potentially send 100 trying
        if method == "INVITE":
            self.add_scenario(f"""
                              <recv response="100" optional="true"></recv>
                              """)
        self.increment()

    def recv(self, method):
        # This only needs to happen on the first invite
        if self.proxy and method == "INVITE" and self.first_invite:
            action = """
            <action>
                <ereg regexp="sip:.*@" search_in="hdr" header="To: " assign_to="req_to" />
            </action>
            """
            self.first_invite = False
        else:
            action = ""

        self.add_scenario(f"""
        <recv request="{method}">{action}</recv>
        """)
        self.increment()

    def recv_response(self, response_code, optional="false"):
        if (response_code in ["180", "183", "200"]) and self.proxy:
            rrs = "rrs=\"true\""
        else:
            rrs = ""

        self.add_scenario(f"""
        <recv response="{response_code}" optional="{optional}" {rrs}></recv>
        """)
        self.increment()

    def send_response(self, response_code, arguments):
        if self.proxy and self.is_uas:
            contact = "[$req_to][local_ip]:[local_port];transport=[transport]"
        else:
            contact = "<sip:[local_ip]:[local_port];transport=[transport]>"
        self.add_scenario(f"""
        <send>
            <![CDATA[
                {response_code}
                {"[last_Via:]" if self.proxy else ""}
                [last_From:]
                [last_To:];tag=[call_number]
                [last_Call-ID:]
                [last_CSeq:]
                {"[last_Record-Route:]" if self.proxy else ""}
                Contact: {contact} 
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

        with open(outfile, 'w') as output:
            output.write(output_string)
