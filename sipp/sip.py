"""
INVITE = Establishes a session
ACK = Confirms an INVITE request
BYE = Ends a session
CANCEL = Cancels establishing of a session
REGISTER = Communicates user location (host name, IP)
OPTIONS = Communicates information about the capabilities of the calling and receiving SIP phones
PRACK = Provisional Acknowledgement
SUBSCRIBE = Subscribes for Notification from the notifier
NOTIFY = Notifies the subscriber of a new event
PUBLISH = Publishes an event to the Server
INFO = Sends mid session information
REFER = Asks the recipient to issue call transfer
MESSAGE = Transports Instant Messages
UPDATE = Modifies the state of a session
"""

# It is assumed that each function is passed an arguments dictionary with the following values, they can be empty
"""
    arguments = {
        "caller": "",
        "callee": "",
        "scenario_name": "",
        "subscriber": "",
        "event": ""
    }
"""

class Actions:

    # This assumes a hop through kamailio 
    # The typical routing would be testbox -> kamailio -> oca
    def __basicKamActions(self):
        self.via = 2
        self.routes = 1

        return """
        <action>
            <ereg regexp=".*" search_in="hdr" header="CSeq:"  assign_to="invite_cseq"/>
            <ereg regexp=".*" search_in="hdr" header="Via:" occurrence="1" assign_to="via_1"/>
            <ereg regexp=".*" search_in="hdr" header="Via:" occurrence="2" assign_to="via_2"/>
            <ereg regexp=".*" search_in="hdr" header="Record-Route:"  occurrence="1" assign_to="route_1"/>
            <assignstr assign_to="local_tag" value="[pid]-[call_number]" />
        </action>
        """

    call = {
        "BASIC": __basicKamActions
    }

    def __init__(self, action_type):
        self.via = 0
        self.routes = 0

        self.action = self.call[action_type](self)

    # Return constructed actions from variables we've stored
    def get_routes(self):
        routes = ""
        for i in range(self.routes):
            routes += f"Record-Route: [$route_{i+1}]\n"
        return routes

    def get_via(self):
        via = ""
        for i in range(self.via):
            via += f"Via: [$via_{i+1}]\n"
        return via
    
    def use_via(self, method):
        NOT_ALLOWED_METHODS = ["183", "180", "100"]

        for mth in NOT_ALLOWED_METHODS:
            if mth in method:
                return False
            
        return True

class Methods:

    def __INVITE(sipp_agent, arguments):
        return f"""
    <![CDATA[  
        INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
        Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
        {arguments["routes"]}
        From: sipp <sip:{arguments["caller"]}@[local_ip]:[local_port]>;tag=[pid]-[call_number]
        To: sut <sip:[service]@[remote_ip]:[remote_port]>
        Call-ID: [call_id]
        CSeq: [cseq] INVITE
        Supported: 100rel
        Contact: <sip:{arguments["caller"]}@[local_ip]:[local_port];user=phone>
        Allow: REGISTER,OPTIONS,INVITE,ACK,CANCEL,BYE,NOTIFY,PRACK,REFER,INFO,SUBSCRIBE,UPDATE
        Subject: {arguments["scenario_name"]}
        {"Content-Type: application/sdp" if arguments["sdp"] != "" else ""}
        Content-Length: [len]

        {arguments["sdp"]}
    ]]>
        """

    def __ACK(sipp_agent, arguments):
        return f"""
        <![CDATA[
            ACK [next_url] SIP/2.0
            Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch-{sipp_agent.counter}]
            [last_From:]
            [last_To:]
            [last_Call-ID:]
            {arguments["routes"]}
            CSeq: [cseq] ACK
            Max-Forwards: 70
            Subject: {arguments["scenario_name"]}
            {"Content-Type: application/sdp" if arguments["sdp"] != "" else ""}
            Content-Length: [len]

            {arguments["sdp"]}
        ]]>
        """
    
        # TODO: we can insert an audio stream here if we want using:
        """
        <action>
            <exec rtp_stream="alaw08m.wav,-1"/>
        </action>  
        """

    def __BYE(sipp_agent, arguments):
        return f"""
        <![CDATA[
            BYE [next_url] SIP/2.0
            Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
            From: sipp  <sip:{arguments["caller"]}@[local_ip]:[local_port]>;tag=[pid]-[call_number]
            To: sut  <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
            [last_Call-ID:]
            [routes]
            CSeq: [cseq] BYE
            Contact: <sip:{arguments["caller"]}@[local_ip]:[local_port]>
            Reason: Q.850;cause=16;text="Terminated"
            {"Content-Type: application/sdp" if arguments["sdp"] != "" else ""}
            Content-Length: [len]

            {arguments["sdp"]}
        ]]>
        """

    def __CANCEL(sipp_agent, arguments):
        return f"""
        <![CDATA[
            CANCEL sip:{arguments["caller"]}@[remote_ip]:[remote_port] SIP/2.0
            Via: SIP/2.0/[transport] [local_ip]:[local_port]
            [last_From:]
            [last_To:]
            [last_Call-ID:]
            CSeq: [last_cseq_number:] CANCEL
            Contact: <sip:{arguments["caller"]}@[local_ip]:[local_port]>
            Reason: Q.850;cause=16;text=Terminated
            Max-Forwards: 70
            {"Content-Type: application/sdp" if arguments["sdp"] != "" else ""}
            Content-Length: [len]

            {arguments["sdp"]}
        ]]>
    """

    def __REGISTER(sipp_agent, arguments):
        return f"""
        <![CDATA[
            REGISTER sip:[remote_ip] SIP/2.0
            Via: SIP/2.0/[transport] [local_ip]:[local_port]
            To: <sip:[field0]@[remote_ip]:[remote_port]>
            From: <sip:[field0]@[remote_ip]:[remote_port]>
            Contact: <sip:[field0]@[local_ip]:[local_port]>;transport=[transport]
            Expires: 20
            Call-ID: [call_id]
            CSeq: [cseq+1] REGISTER
            {"Content-Type: application/sdp" if arguments["sdp"] != "" else ""}
            Content-Length: [len]

            {arguments["sdp"]}
        ]]>
    """

    def __OPTIONS(sipp_agent, arguments):
        return f"""
        <![CDATA[
            OPTIONS sip:{arguments["callee"]}@[remote_ip]:[remote_port] SIP/2.0
            Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
            From: "caller" <sip:[field0]@[remote_ip]>;tag=[pid]-[call_number]
            To: <sip:[field1]@[remote_ip]>
            Call-ID: [call_id]
            CSeq: [cseq+1] OPTIONS
            Subject: {arguments["scenario_name"]}
            User-Agent: SIPp
            Accept: application/sdp
            Max-Forwards: 70
            Content-Length: [len]
        ]]>
        """

    def __PRACK(sipp_agent, arguments):
        return f"""
        <![CDATA[
            PRACK [next_url] SIP/2.0
            Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
            [last_From:]
            [last_To:]
            [last_Call-ID:]
            {arguments["routes"]}
            CSeq: [cseq] PRACK
            Max-Forwards: 70
            {"Content-Type: application/sdp" if arguments["sdp"] != "" else ""}
            Subject: {arguments["scenario_name"]}
            Content-Length: [len]

            {arguments["sdp"]}
        ]]>
        """

    def __SUBSCRIBE(sipp_agent, arguments):
        return f"""
        <![CDATA[
            SUBSCRIBE sip:[remote_ip] SIP/2.0
            Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
            From: <sip:[field0]@[remote_ip]:[remote_port]>;tag=[pid]-[call_number]
            To: <sip:[field0]@[remote_ip]:[remote_port]>
            Contact: <sip:[field0]@[local_ip]:[local_port];transport=[transport]>
            Call-ID: [call_id]
            CSeq: [cseq+1] SUBSCRIBE
            Event: {arguments["event"]}
            Expires: 3600
            Max-Forwards: 70
            User-Agent: SIPp
            Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, PRACK, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, UPDATE
            Content-Length: [len]

            {arguments["sdp"]}
        ]]>
        """

    def __NOTIFY(sipp_agent, arguments):
        return f"""
        <![CDATA[
            NOTIFY sip:{arguments["subscriber"]} SIP/2.0
            Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
            From: sip:[caller]@[local_ip]:[local_port]>;tag=[pid]-[call_number]
            To: <sip:[subscriber]@[remote_ip]:[remote_port]>
            Contact: <sip:{arguments["caller"]}@[local_ip]:[local_port]>
            Call-ID: [call_id]
            CSeq: [cseq+1] NOTIFY
            Event: {arguments["event"]}
            Subscription-State: active;expires=3600
            Max-Forwards: 70
            Allow-Events: talk, hold, refer, conference
            Content-Type: application/simple-message-summary
            Content-Length: [len]

            {arguments["sdp"]}
        ]]>
        """

    def __PUBLISH(sipp_agent, arguments):
        return f"""
        <![CDATA[
            PUBLISH sip:testuser@[domain]:5060 SIP/2.0
            Via: SIP/2.0/UDP [local_ip]:[local_port];rport;branch=[branch]
            From: testuser <sip:testuser@[domain]>;tag=[pid]-[call_number]
            To: testuser <sip:testuser@[domain]>
            CSeq: [cseq+1] PUBLISH
            Request-URI: sip:[domain]:5060
            Contact: <sip:testuser@[local_ip]:[local_port]>
            Expires: 60
            Max-Forwards: 70
            User-Agent: SIPp
            Event: message-summary
            Content-Type: application/simple-message-summary
            Content-Length: [len]
            
            {arguments["sdp"]}
        ]]>
        """

    def __INFO(sipp_agent, arguments):
        return f"""
        <![CDATA[
            INFO [$1] SIP/2.0
            Via: SIP/2.0/[transport] [local_ip]:[local_port]
            From: "caller"<sip:[field0]@[remote_ip]>;tag=[pid]-[call_number]
            To: <sip:[field1]@[remote_ip]:[remote_port]>
            Call-ID: [call_id]
            CSeq: [cseq+1] INFO
            Content-Type: application/dtmf-relay
            Max-Forwards: 70
            Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, MESSAGE, SUBSCRIBE, NOTIFY, INFO, REFER
            Contact: <sip:[subscriber]@[remote_ip]:[remote_port]>
            Event: dtmf-relay
            Content-Length: [len]
            
            {arguments["sdp"]}
        ]]>
        """

    def __REFER(sipp_agent, arguments):
        return f"""
        <![CDATA[
            REFER sip:{arguments["callee"]}@[remote_ip] SIP/2.0
            Via: SIP/2.0/[transport] [local_ip]:[local_port]
            From: sip:[caller]@[local_ip]:[local_port]>;tag=[pid]-[call_number]
            To: <sip:[callee]@[remote_ip]>
            Contact: <sip:{arguments["caller"]}@[local_ip]:[local_port]>
            Call-ID: [call_id]
            CSeq: [cseq+1] REFER
            Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, INFO, REFER, MESSAGE
            Max-Forwards: 70
            Refer-To: <sip:[callee]@[remote_ip];user=phone>
            Refer-Sub: <sip:[caller]@[local_ip]:[local_port]>
            Content-Length: [len]

            {arguments["sdp"]}
        ]]>
        """

    def __MESSAGE(sipp_agent, arguments):
        return f"""
        <![CDATA[

            MESSAGE sip:{arguments["callee"]}@[remote_ip] SIP/2.0
            Via: SIP/2.0/[transport] [local_ip]:[local_port]
            From: "caller"<sip:[field0]@[remote_ip]>;tag=[pid]-[call_number]
            To: <sip:[callee]@[remote_ip]>
            Call-ID: [call_id]
            CSeq: [cseq+1] MESSAGE
            Max-Forwards: 70
            Content-Type: text/plain
            Contact: <sip:[subscriber]@[remote_ip]:[remote_port]>
            User-Agent: SIPp
            Subject: {arguments["scenario_name"]}
            Content-Length: [len]

            {arguments["sdp"]}
        ]]>
        """

    def __UPDATE(sipp_agent, arguments):
        return f"""
        <![CDATA[
            UPDATE [$1] SIP/2.0
            Via: SIP/2.0/[transport] [local_ip]:[local_port]
            To: <sip:[remote_ip]:[remote_port]>
            From: "caller" <sip:[field0]@[remote_ip]>;tag=[pid]-[call_number]
            Call-ID: [call_id]
            CSeq: [cseq+1] UPDATE
            Max-Forwards: 70
            User-Agent: SIPp
            Content-Length: [len]
            
            {arguments["sdp"]}
        ]]>
        """
    call = {
    "INVITE": __INVITE,
    "ACK": __ACK,
    "BYE": __BYE,
    "CANCEL": __CANCEL,
    "REGISTER": __REGISTER,
    "OPTIONS": __OPTIONS,
    "PRACK": __PRACK,
    "SUBSCRIBE": __SUBSCRIBE,
    "NOTIFY": __NOTIFY,
    "PUBLISH": __PUBLISH,
    "INFO": __INFO,
    "REFER": __REFER,
    "MESSAGE": __MESSAGE,
    "UPDATE": __UPDATE
    }