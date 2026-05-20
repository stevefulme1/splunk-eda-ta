# Red Hat Event Driven Ansible Add-on for Splunk

## Description
The add-on provides custom alert actions to send Splunk events to Event Driven Ansible.
Currently webhook, and Kafka methods are supported. Works with [generic EDA event source plugins](https://github.com/ansible/event-driven-ansible/blob/main/extensions/eda/plugins/event_source/README.md) for webhook, kafka.

## Compatibility
* Splunk Enterprise 9.3, 9.4, 10.0, 10.1, 10.2
* Splunk Cloud Platform
* Ansible Automation Platform 2.4+

## Documentation

## Build
This add-on is built with Splunk's [UCC Generator](https://github.com/splunk/addonfactory-ucc-generator).  Install `ucc-gen` [per the instructions](https://splunk.github.io/addonfactory-ucc-generator/#installation). 

Consider using a python virtual environment: [Getting Started with UCC](https://splunk.github.io/addonfactory-ucc-generator/quickstart/)
Then, execute the following from the command line in the root of this repository to build the add-on:

    ucc-gen build --ta-version=<version>

Example:

    ucc-gen build --ta-version=1.0.0

The add-on will be built in an `output` directory in the root of the repository.

## Package

    ucc-gen package --path=./output/ansible_addon_for_splunk

## Usage

### Configuration
Configuration of a service account, depends on the type of connection, and desired authentication method.
Currently webhook supports none, basic, or API key based authentication.
Kafka supports none, SASL plaintext, or with SSL.

Sending one or more events can be done in a variety of ways within Splunk:
* Saved Search Alert Action
* Custom Command
* ITSI Episode Alert Action
* Enterprise Security Adaptive Response Action

## Community

- [Contributing](CONTRIBUTING.md) - How to contribute to this project
- [Code of Conduct](CODE_OF_CONDUCT.md) - Ansible Community Code of Conduct
- [Security Policy](SECURITY.md) - How to report security vulnerabilities
- [License](COPYING) - GPL-3.0

