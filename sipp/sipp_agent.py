from sipp.sip import Methods
from sipp.sip import Actions

import xmlformatter

class sipp_agent:

    rrs_string = "rrs=\"true\""

    def __init__(self, number, scenario_name="SIPp Scenario"):
        
        self.number = number
        self.scenario_name = scenario_name

        # SIPP Scenario as string
        self.scenario = []

        # Method generator
        self.sip_methods = Methods()

        # Flag to save routes and re-use in [routes] config
        self.saved_routes = False

        # Increments for each action, allows us to use branch automatically
        self.counter = 0

        # Store routes / via headers on UAS side
        self.use_actions = False
        self.actions = None

    def add_scenario(self, content):
        self.scenario.append(content)

    # Keep track of our method increments, useful for responding to correct branch
    def increment(self):
        self.counter += 1
        #self.wait(200)

    def is_method(self, method):
        return method in self.sip_methods.call
    
    def use_rrs(self, response_code):
        RRS_CODES = [
            "183",
            "180",
            "INVITE"
        ]
        if "183" in response_code or "180" in response_code:
            self.saved_routes = True

        if "INVITE" in response_code:
            self.saved_routes = True
            self.use_actions = True
            self.actions = Actions("BASIC")
        
        for code in RRS_CODES:
            if code in response_code:
                return True
        return False

    def send(self, method, arguments):
        if (self.saved_routes):
            arguments["routes"] = "[routes]"
        else:
            arguments["routes"] = ""

        self.add_scenario(f"""
        <send>
            {self.sip_methods.call[method](self, arguments)}
        </send>
        """)
        self.increment()

    def recv(self, method):
        self.add_scenario(f"""
        <recv request="{method}" {self.rrs_string if self.use_rrs(method) else ""}>
        {self.actions.action if self.use_rrs(method) else ""}
        </recv>
        """)
        self.increment()

    def recv_response(self, response_code, optional="false"):        
        self.add_scenario(f"""
        <recv response="{response_code}" {self.rrs_string if self.use_rrs(response_code) else ""}
            optional="{optional}">
        </recv>
        """)
        self.increment()

    def send_response(self, status_line, arguments):
        self.add_scenario(f"""
        <send>
            <![CDATA[
                {status_line}
                {self.actions.get_via() if self.actions.use_via(status_line) else "[last_Via:]"}
                [last_From:]
                [last_To:];{"tag=[$local_tag]" if self.use_actions else "tag=[call_number]"}
                {self.actions.get_routes() if "200" not in status_line else "[routes]"}
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
                    output += '\n' + (' ' * (current_indentation + INDENTATION) + line.lstrip())
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
        formatter = xmlformatter.Formatter(indent="4", correct = True)

        with open(outfile, 'w') as output:
            output.write(formatter.format_string(output_string).decode())
            
