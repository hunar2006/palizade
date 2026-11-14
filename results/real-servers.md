Run on 2026-11-05: `node eval/real-servers.mjs eval/real-servers.example.yaml`

| Server | Catalog | Tools | Source | Sink | Pure | Unknown | Metadata flags | Withheld |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| filesystem | filesystem | 14 | 9 | 4 | 1 | 0 | 0 | 0 |
| memory | memory | 9 | 3 | 6 | 0 | 0 | 0 | 0 |
| sequential-thinking | sequential-thinking | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
| everything | - | 16 | 6 | 8 | 0 | 2 | 0 | 0 |
| playwright | playwright | 25 | 7 | 18 | 0 | 0 | 0 | 0 |
| fetch | fetch | 1 | 0 | 1 | 0 | 0 | 0 | 0 |
| git | git | 14 | 8 | 6 | 0 | 0 | 0 | 0 |
| time | time | 3 | 0 | 0 | 3 | 0 | 0 | 0 |

Total: 83 tools from 8 servers.

Unknown tools (blocked on untrusted servers until classified):
- everything: echo, trigger-long-running-operation

No metadata flags and no tools withheld.
