# Cloud-setup

Cloud-setup is an automated setup tool written in Python3.

## What is the program for?

This program is for setting up iptables on a VM instance of Oracle Cloud.
ufw is not available by default in Oracle Cloud and it is recommended to use iptables, which are provided from the beginning.
This program sets up iptables based on the rules specified.

## Usage

It works by running `main.py`.
You will need to rewrite variables in the source code as needed.

```
$ git clone git@github.com:mcplaynetwork/Cloud-setup.git
$ python3 main.py
```

This program is intended to run in Cloud-init.
