# Darknode CLI

The terminal edition of Darknode — a single command that drives a full security
toolkit and hosts **Nexus**, the AI coding agent. Recon, exploitation helpers,
practice labs, governance, and an autonomous AI layer, all from your shell.

## Architecture

```
   You (a command)
        |
        v
   darknode.js  (dispatch + first-run setup)
        |
        +--> nexus ------> Nexus engine (lib/nexus) ---> Ollama (local) | Claude / API (cloud)
        |                    plan -> act -> observe, cost meter, /undo
        |
        +--> toolkit ----> external tools: nmap · sqlmap · nuclei · ffuf · httpx ...
        |
        +--> governance -> identity · usage ledger · compliance bundle
        |
        +--> lab --------> docker practice targets (spin up / tear down)
        v
   Results in your terminal
```

Most subcommands run through the toolkit or governance layers; `nexus` (aliases
`code`, `ai`) hands the turn to the AI engine, which edits files and runs commands
against your workspace with a live token/cost readout.

## Project Structure

```
darknode-cli/
├── darknode.js            # entry point + command dispatch
├── lib/
│   ├── cli/              # command implementations & shared CLI helpers
│   ├── nexus/            # the Nexus AI-coder engine
│   ├── governance/       # identity, usage ledger, compliance/policy
│   └── toolkit/          # external-tool drivers (recon / web / passwords / ...)
├── scripts/              # build & release helpers
├── test/                 # test suite (npm test)
├── docs/                 # command reference & guides
│   └── NEXUS.md          # complete Nexus guide (every command explained)
├── package.json
└── README.md
```

## Installation

```bash
# from source (Node 18+)
git clone https://github.com/Darknode-Official/darknode-cli
cd darknode-cli && npm install && node darknode.js

# or grab a standalone binary from Releases and put it on PATH
```

## Usage

```bash
darknode nexus              # the AI coding agent (interactive TUI)
darknode nexus "fix auth"   # one-shot task
darknode nexus --engine ollama   # local, private models
darknode <tool> ...         # drive the security toolkit
```

## Documentation

See [docs/NEXUS.md](docs/NEXUS.md) for the complete Nexus guide — every command,
feature, and configuration option explained.

## Running Tests

```bash
npm test
```

## Engines

| Engine | Models | Cost |
|--------|--------|------|
| Claude | opus, sonnet, haiku, fable | Subscription or API |
| Gemini | gemini-2.5-pro, flash | API |
| Codex | gpt-5-codex, o4-mini | API |
| OpenCode | any configured provider | API |
| Aider | any configured model | API |
| Ollama | any local model | Free |

## Key Features

- **6 AI engines** behind one interface
- **Cost saving**: `/cowork`, `/lean`, `/cheap`, `/budget`, `/estimate`
- **Multi-engine**: `/race`, `/ensemble`, `/bench`
- **Code tools**: `/agents`, `/plan`, `/review`, `/commit`, `/undo`
- **Security**: `/guard`, `/redact`, `/secrets`, `/policy`, `/audit`
- **Customizable**: `.nexus/NEXUS.md`, custom commands, styles, hooks, MCP servers

## Security

The CLI can run external tools and, via Nexus, edit files and run commands. Use it
only against systems you're authorized to test, and prefer the local `ollama` engine
for sensitive code. Credentials are never stored in source.

Users bring their own AI API keys. No AI runs on Darknode servers.

## License

See `LICENSE`.
