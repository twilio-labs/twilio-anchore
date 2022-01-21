# Twilio Anchore Python Library

![Twilio Logo](https://www.twilio.com/docs/static/company/img/badges/red/twilio-badge-red.046b4a20c.png "Twilio")

Library developed in Python that facilitates the use of some features of the Anchore API.    
The main purpose of this library is to ease the execution of those Anchore API features that allow to check the security of container images, such as:
- Get the information of the container images
- Obtain the vulnerabilities of the container images
- Obtain the contents of container images
- Obtaining information about the base image of the container images
- Evaluate policies against container images
- Obtain information about container images running on Kubernetes clusters

**NOTE:** This library is not intended to perform Anchore administration tasks, such as creating accounts/users or configuring container registries, etc.

## Quickstart

Need to start now?

```python
from anchore.service import AnchoreService

anchore_service = AnchoreService("https://analyzer.anchore.com", "anchoreuser", "password")
response = anchore_service.get_image("ubuntu:latest")
if response.get_status_code() == 200:
  ubuntu_image = response.get_result()
```

## Installation

To install twilio-anchore execute the following commands:
```python
git clone https://github.com/twilio-labs/twilio-anchore.git
cd twilio-anchore
python3 -m pip install .
```

## Usage

See the documentation for full details:
- [Anchore Service](./docs/anchore_service.md)
- [Anchore classes](./docs/anchore_models.md)

## Limitations
Some of these functionalities belong to the Enterprise version of Anchore, so it is necessary to review the documentation of each of the methods to know which ones require the Enterprise version.  
**If you have the Enterprise version of Anchore, all methods can be used without any restrictions.**

## Contributing
For guidance on setting up a development environment and how to make a contribution to this project, see the contributing guidelines.
