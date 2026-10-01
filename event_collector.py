import time
import win32evtlog


SECURITY_LOG = "Security"


# Windows Security Event IDs we want to investigate
INTERESTING_EVENT_IDS = {
    4624: "Successful login",
    4625: "Failed login",
    4648: "Explicit credential use",
    4688: "Process created",
}


def collect_security_events(max_events=100):
    """
    Read recent Windows Security events.
    This function is read-only and does not modify event logs.
    """

    events = []
    handle = None

    try:
        handle = win32evtlog.OpenEventLog(
            None,
            SECURITY_LOG
        )

        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        records = win32evtlog.ReadEventLog(
            handle,
            flags,
            0
        )

        while records and len(events) < max_events:

            for event in records:

                event_id = event.EventID & 0xFFFF

                if event_id not in INTERESTING_EVENT_IDS:
                    continue

                # Windows event insertion strings.
                # Some events may not contain any strings.
                strings = event.StringInserts

                if strings is None:
                    strings = []

                # Convert all event strings to normal text.
                strings = [
                    str(value)
                    for value in strings
                ]

                event_data = {
                    "event_id": event_id,

                    "event_type": INTERESTING_EVENT_IDS[
                        event_id
                    ],

                    "source": event.SourceName,

                    "record_number": event.RecordNumber,

                    "time_generated": str(
                        event.TimeGenerated
                    ),

                    "computer": event.ComputerName,

                    # Important:
                    # The investigation tools search this field.
                    "strings": strings,
                }

                events.append(event_data)

                if len(events) >= max_events:
                    break

            if len(events) >= max_events:
                break

            records = win32evtlog.ReadEventLog(
                handle,
                flags,
                0
            )

    except Exception as error:

        print(
            "Could not read Windows Security logs."
        )

        print(
            "Error:",
            error
        )

    finally:

        if handle:

            try:
                win32evtlog.CloseEventLog(
                    handle
                )
            except Exception:
                pass

    return events


def get_new_events(last_record_number):
    """
    Return only events newer than the checkpoint.
    """

    events = collect_security_events()

    new_events = [
        event
        for event in events
        if event["record_number"] > last_record_number
    ]

    return new_events


# ============================================================
# AGENT INVESTIGATION TOOLS
# ============================================================


def search_auth_events(
    username=None,
    event_id=None
):
    """
    Search Windows authentication events.

    Event IDs:
        4624 = Successful login
        4625 = Failed login
        4648 = Explicit credential use
    """

    events = collect_security_events(
        max_events=100
    )

    results = [
        event
        for event in events
        if event.get("event_id")
        in (4624, 4625, 4648)
    ]

    if username:

        username = username.lower()

        results = [
            event
            for event in results
            if username in str(
                event.get("strings", [])
            ).lower()
        ]

    if event_id:

        results = [
            event
            for event in results
            if event.get("event_id") == event_id
        ]

    return results


def search_process_events():
    """
    Search Windows process creation events.
    Event ID 4688 = Process created.
    """

    events = collect_security_events(
        max_events=100
    )

    return [
        event
        for event in events
        if event.get("event_id") == 4688
    ]


def search_events_by_user(username):
    """
    Search Windows Security events by username.
    """

    events = collect_security_events(
        max_events=100
    )

    username = username.lower()

    return [
        event
        for event in events
        if username in str(
            event.get("strings", [])
        ).lower()
    ]


def search_events_by_ip(ip_address):
    """
    Search Windows Security events by IP address.
    """

    events = collect_security_events(
        max_events=100
    )

    return [
        event
        for event in events
        if ip_address in str(
            event.get("strings", [])
        )
    ]


def search_events_by_host(hostname):
    """
    Search Windows Security events by hostname.
    """

    events = collect_security_events(
        max_events=100
    )

    hostname = hostname.lower()

    return [
        event
        for event in events
        if hostname in str(
            event.get("computer", "")
        ).lower()
    ]


# ============================================================
# STANDALONE EVENT COLLECTION TEST
# ============================================================


def main():

    print(
        "Windows Agent AI Threat Hunter"
    )

    print(
        "Starting real-time event collection...\n"
    )

    security_events = collect_security_events()

    if security_events:

        last_record_number = max(
            event["record_number"]
            for event in security_events
        )

    else:

        last_record_number = 0

    print(
        f"Starting checkpoint: "
        f"{last_record_number}"
    )

    print(
        "Monitoring for new security events...\n"
    )

    try:

        while True:

            time.sleep(5)

            new_events = get_new_events(
                last_record_number
            )

            for event in new_events:

                print(
                    "\nNew security event detected:"
                )

                print(event)

                last_record_number = max(
                    last_record_number,
                    event["record_number"]
                )

    except KeyboardInterrupt:

        print(
            "\nEvent collection stopped."
        )


if __name__ == "__main__":
    main()