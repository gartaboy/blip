# BLIP CLI

```
 ____  _     ___ ____    ____ _     ___
| __ )| |   |_ _|  _ \  / ___| |   |_ _|
|  _ \| |    | || |_) || |   | |    | |
| |_) | |___ | ||  __/ | |___| |___ | |
|____/|_____|___|_|     \____|_____|___|
        ~ tiny LAN messenger ~
```

Dependency-free CLI for the BLIP LAN mesh: discover peers, exchange messages, and run a JSONL inbox over UDP 42069 / TCP 42070. Requires Python 3.9+ (standard library only).

## Usage

```sh
python cli.py identity --id 1 --name alice          # create/show local identity
python cli.py discover --timeout 8                   # list peers on the LAN
python cli.py send --peer 2 --text "hello"           # send a message
python cli.py send --peer 2 --file message.txt --output receipt.json
python cli.py listen --output inbox.jsonl            # run TCP inbox, write JSONL
python cli.py ping --peer 2                          # TCP round-trip time
```

Common flags (`--identity`, `--id`, `--name`, `--tcp-port`, `--udp-port`, `--ip`, `--broadcast`, `-v`, `-q`) may be placed before or after the subcommand. Run `python cli.py <command> --help` for the full list.

## Local test (two nodes on one machine)

```sh
python cli.py --identity a.json identity --id 1 --name A
python cli.py --identity b.json identity --id 2 --name B
python cli.py --identity b.json listen --tcp-port 42071 --udp-port 42169 --no-announce --timeout 15 --output inbox.jsonl &
python cli.py --identity a.json send --tcp-port 42072 --udp-port 42169 --peer 2 --peer-ip 127.0.0.1 --peer-port 42071 --no-announce --text "hello from A"
```

## Security

The identity file contains a private seed. Keep it out of version control (see `.gitignore`).

## Author and origin

- **Author:** [@gartaboy](https://github.com/gartaboy)
- **Original project:** [krwg/blip](https://github.com/krwg/blip) — BLIP peer-to-peer LAN messenger (Electron + WebRTC), licensed under GPL-3.0. This CLI is a compatible command-line client for the same LAN mesh protocol.
