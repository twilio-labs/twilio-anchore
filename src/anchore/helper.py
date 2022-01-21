import requests
from pydantic import AnyHttpUrl


def send_get_request_basic_auth(url: AnyHttpUrl, user: str, password: str, verify: bool = True):
    return requests.get(url, auth=(user, password), verify=verify)


def send_post_request_basic_auth(url: AnyHttpUrl, user: str, password: str, payload: dict, verify: bool = True):
    return requests.post(url, auth=(user, password), json=payload, verify=verify)
