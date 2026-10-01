import time
import json

from openai import OpenAI

from event_collector import (
    collect_security_events,
    get_new_events,
    search_auth_events,
    search_process_events,
    search_events_by_user,
    search_events_by_ip,
    search_events_by_host,
)

client = OpenAI()

MODEL = "gpt-4.1-mini"

TOOLS = [
    {
        "type": "function",
        "name": "search_auth_events",
        "description": "Search Windows authentication events.",
        "parameters": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "Windows username to search for."
                },
                "event_id": {
                    "type": "integer",
                    "description": "Windows event ID such as 4624 or 4625."
                }
            },
            "required": []
        }
    },
    {
        "type": "function",
        "name": "search_process_events",
        "description": "Search Windows process creation events.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "type": "function",
        "name": "search_events_by_user",
        "description": "Search Windows Security events by username.",
        "parameters": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "Windows username to search for."
                }
            },
            "required": ["username"]
        }
    },
    {
        "type": "function",
        "name": "search_events_by_ip",
        "description": "Search Windows Security events by IP address.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "IP address to search for."
                }
            },
            "required": ["ip_address"]
        }
    },
    {
        "type": "function",
        "name": "search_events_by_host",
        "description": "Search Windows Security events by hostname.",
        "parameters": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "Hostname to search for."
                }
            },
            "required": ["hostname"]
        }
    }
]


def run_tool(name, arguments):
    if name == "search_auth_events":
        return search_auth_events(**arguments)

    if name == "search_process_events":
        return search_process_events()

    if name == "search_events_by_user":
        return search_events_by_user(**arguments)

    if name == "search_events_by_ip":
        return search_events_by_ip(**arguments)

    if name == "search_events_by_host":
        return search_events_by_host(**arguments)

    return {"error": f"Unknown tool: {name}"}


def investigate_with_llm(events):
    instructions = """
You are a defensive Windows threat-hunting analyst investigating
an authorized Windows laboratory computer.

Use only evidence returned by the provided tools.

Do not invent events or evidence.

Do not execute commands or modify the computer.

Do not delete or modify Windows event logs.

Clearly distinguish observations from conclusions.

Identify possible false positives and missing evidence.

Recommend defensive investigation steps only.

For each event:

- State the Windows Event ID.
- Explain what the event represents.
- Identify the available evidence.
- Explain whether the activity appears potentially suspicious,
  benign, or inconclusive.
- Do not claim that one event proves a compromise.
"""

    try:
        response = client.responses.create(
            model=MODEL,
            instructions=instructions,
            input=json.dumps(events, default=str),
            tools=TOOLS
        )

    except Exception as error:
        print(f"AI investigation error: {error}")
        return

    for _ in range(5):

        function_calls = [
            item
            for item in response.output
            if getattr(item, "type", None) == "function_call"
        ]

        if not function_calls:
            print("\n===== AI INVESTIGATION REPORT =====")

            if response.output_text:
                print(response.output_text)
            else:
                print("No AI report was returned.")

            print("===== END REPORT =====\n")
            return

        tool_outputs = []

        for call in function_calls:

            try:
                arguments = json.loads(call.arguments or "{}")

                result = run_tool(
                    call.name,
                    arguments
                )

                output = json.dumps(
                    result,
                    default=str
                )

            except Exception as error:
                output = json.dumps({
                    "error": str(error)
                })

            tool_outputs.append({
                "type": "function_call_output",
                "call_id": call.call_id,
                "output": output
            })

        try:
            response = client.responses.create(
                model=MODEL,
                instructions=instructions,
                previous_response_id=response.id,
                input=tool_outputs,
                tools=TOOLS
            )

        except Exception as error:
            print(f"AI investigation error: {error}")
            return

    print("AI investigation stopped after reaching the tool-call limit.")


def main():

    print("Starting Windows Agent AI Threat Hunter...")
    print("Connecting to Windows Security events...\n")

    existing_events = collect_security_events()

    if existing_events:
        last_record_number = max(
            event["record_number"]
            for event in existing_events
        )
    else:
        last_record_number = 0

    print(f"Starting checkpoint: {last_record_number}")
    print("Monitoring for new security events...\n")

    try:

        while True:

            time.sleep(5)

            new_events = get_new_events(
                last_record_number
            )

            if not new_events:
                continue

            print(
                f"\nDetected {len(new_events)} new event(s)."
            )

            for event in new_events:

                print("\nNew security event detected:")

                print(
                    json.dumps(
                        event,
                        indent=2,
                        default=str
                    )
                )

                last_record_number = max(
                    last_record_number,
                    event["record_number"]
                )

            investigate_with_llm(new_events)

    except KeyboardInterrupt:
        print("\nThreat Hunter stopped.")


if __name__ == "__main__":
    main()