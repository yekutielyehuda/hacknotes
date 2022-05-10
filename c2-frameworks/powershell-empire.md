# PowerShell Empire

Empire 4 is a post-exploitation framework that includes a pure-PowerShell Windows agents, Python 3.x Linux/OS X agents, and C# agents. It is the merger of the previous PowerShell Empire and Python EmPyre projects. The framework offers cryptologically-secure communications and flexible architecture.

https://github.com/BC-SECURITY/Empire


Keep up-to-date in their blog at:

https://www.bc-security.org/blog


It also has wiki:

https://bc-security.gitbook.io/empire-wiki/


## Installation

The official installation process can be found in their wiki:

https://bc-security.gitbook.io/empire-wiki/quickstart/installation


Install on Kali:

```sh
sudo apt install powershell-empire
```

Install on Ubuntu:

```sh
git clone --recursive https://github.com/BC-SECURITY/Empire.git
cd Empire
sudo ./setup/install.sh
```

## Run

We can run empire on Debian with:

```sh
sudo empire
```

In Kali Linux:

```sh
sudo powershell-empire
```

