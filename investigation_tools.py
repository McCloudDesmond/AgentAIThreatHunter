from event_collector import (
    search_auth_events,
    search_process_events,
    search_events_by_ip,
    search_events_by_host,
)


def investigate_auth(username=None, event_id=None):
    return search_auth_events(username, event_id)


def investigate_processes():
    return search_process_events()


def investigate_ip(ip_address):
    return search_events_by_ip(ip_address)


def investigate_host(hostname):
    return search_events_by_host(hostname)


INVESTIGATION_TOOLS = {
    "search_auth_events": investigate_auth,
    "search_process_events": investigate_processes,
    "search_events_by_ip": investigate_ip,
    "search_events_by_host": investigate_host,
}