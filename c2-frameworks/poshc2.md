# PoshC2

PoshC2 official documentation: 

https://poshc2.readthedocs.io/en/latest/

## Installation

A bash one-liner is provided which curls down this script and executes it:

```sh
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | sudo bash
```

Alternatively the repository can be cloned down and the install script manually run.

```sh
sudo ./Install.sh
```

You can manually set the PoshC2 installation directory by passing it to the Install.sh script as the -p argument. The default is /opt/PoshC2:

```sh
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | sudo bash -s -- -p /root/PoshC2
```

## PoshC2 Usage

PoshC2 has this well documented:

https://poshc2.readthedocs.io/en/latest/usage/index.html