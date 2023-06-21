"""
Define your custom SIPP actions in this class,
each function should be tied to the call dictionary, the type of action set to use
can be defined with the --action flag on generation
"""


class Actions:

    # This is a basic caller to caller scenario
    def __BASIC(self):
        self.via = 1
        self.routes = 0

        return """
        <action>
            <ereg regexp=".*" search_in="hdr" header="CSeq:"  assign_to="invite_cseq"/>
            <ereg regexp=".*" search_in="hdr" header="Via:" occurrence="1" assign_to="via_1"/>
            <assignstr assign_to="local_tag" value="[pid]-[call_number]" />
        </action>
        """

    # This assumes a hop through kamailio
    # The typical routing would be testbox -> kamailio -> oca
    def __BASIC_KAM(self):
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
        "BASIC": __BASIC,
        "BASIC_KAM": __BASIC_KAM
    }

    def __init__(self, action_type):
        self.via = 0
        self.routes = 0
        self.action_type = action_type

    def xml(self):
        return self.call[self.action_type](self)

    # Return a "Record-Route: " string based on our action
    def get_routes(self):
        routes = ""
        for i in range(self.routes):
            routes += f"Record-Route: [$route_{i+1}]\n"
        return routes

    # Return a "Via: " string based on our action
    def get_via(self):
        via = ""
        for i in range(self.via):
            via += f"Via: [$via_{i+1}]\n"
        return via

    # Determine if VIA headers should be included based on method type
    def use_via(self, method):
        NOT_ALLOWED_METHODS = ["183", "180", "100"]

        for mth in NOT_ALLOWED_METHODS:
            if mth in method:
                return False

        return True
