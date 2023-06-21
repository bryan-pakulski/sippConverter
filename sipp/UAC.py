from sipp import sipp_agent

class UAC(sipp_agent.sipp_agent):
    def __init__(self, callee_number, scenario_name="SIPp Scenario"):
        super().__init__(callee_number, scenario_name=scenario_name)