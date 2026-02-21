# EireScope

**Open-Source Intelligence Investigation Dashboard**

EireScope is a modular OSINT (Open-Source Intelligence) tool designed to help law enforcement and investigators enrich, correlate, and visualize data from multiple intelligence sources through a single unified interface.

Built with a focus on supporting Irish authorities (An Garda Siochana), EireScope consolidates username searches, email enrichment, phone analysis, IP reconnaissance, and domain investigation into one investigator-friendly web dashboard.

## Features

- **Username Search** — Scan 40+ social platforms for matching profiles (Sherlock-like)
- **Email Enrichment** — Breach checks (HIBP), MX validation, provider detection, disposable email detection
- **Phone Analysis** — Irish carrier detection (Vodafone, Three, etc.), E.164 validation, number classification
- **IP Recon** — GeoIP lookup, WHOIS, reverse DNS, proxy/VPN detection
- **Domain Recon** — DNS records (A, MX, NS, TXT), WHOIS, subdomain enumeration via crt.sh
- **Social Media Discovery** — GitHub profile enrichment, Gravatar cross-referencing
- **Entity Relationship Graph** — Interactive D3.js visualization of discovered connections
- **Investigation History** — SQLite-backed persistence of all investigations
- **HTML Report Export** — Professional investigation reports for official use
- **Auto-Detection** — Automatically identifies input type (email, IP, phone, etc.)

## Quick Start

```bash
git clone https://github.com/yourusername/eirescope.git
cd eirescope
python3 run.py
```

Open http://localhost:5000 in your browser.

### Command Line Options

```bash
python3 run.py --host 0.0.0.0 --port 5000
```

## Requirements

- Python 3.8+
- `requests` (HTTP client)
- `beautifulsoup4` (HTML parsing)
- `Jinja2` (template rendering)

All other dependencies use Python standard library (`sqlite3`, `socket`, `subprocess`, `json`, etc.).

Optional system tools for enhanced results:
- `dig` (DNS lookups)
- `whois` (WHOIS queries)

## Architecture

EireScope follows a three-layer architecture:

```
Presentation    Flask-like web UI + D3.js graph visualization
                         |
Coordination    InvestigationEngine orchestrates modules, aggregates results
                         |
Execution       Plugin-based OSINT modules (username, email, phone, IP, domain)
```

### Project Structure

```
eirescope/
├── run.py                          # Entry point
├── config.py                       # Configuration
├── eirescope/
│   ├── core/
│   │   ├── engine.py               # Investigation orchestrator
│   │   ├── entity.py               # Entity/Relationship data models
│   │   ├── plugin_manager.py       # Module auto-discovery
│   │   └── results.py              # Result aggregation
│   ├── modules/
│   │   ├── base.py                 # BaseOSINTModule (plugin interface)
│   │   ├── username_module.py      # Username search (40+ platforms)
│   │   ├── email_module.py         # Email enrichment
│   │   ├── phone_module.py         # Phone number analysis
│   │   ├── ip_module.py            # IP address recon
│   │   ├── domain_module.py        # Domain recon
│   │   └── social_module.py        # Social media discovery
│   ├── web/
│   │   ├── app.py                  # HTTP server & routes
│   │   ├── templates/              # Jinja2 HTML templates
│   │   └── static/                 # CSS, JS (D3.js graph)
│   ├── reporting/
│   │   └── report_generator.py     # HTML report generation
│   ├── db/
│   │   └── database.py             # SQLite persistence
│   └── utils/
│       ├── validators.py           # Input validation
│       ├── http_client.py          # HTTP client with retries
│       └── exceptions.py           # Custom exceptions
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Search landing page |
| `/search` | POST | Form-based search |
| `/api/search` | POST | JSON API search |
| `/investigation/<id>` | GET | Investigation results page |
| `/api/investigation/<id>` | GET | Investigation data (JSON) |
| `/history` | GET | Investigation history |
| `/api/history` | GET | History (JSON) |
| `/export/<id>` | GET | Download HTML report |
| `/api/modules` | GET | List available modules |

### API Search Example

```bash
curl -X POST http://localhost:5000/api/search \
  -H "Content-Type: application/json" \
  -d '{"query": "+353871234567", "entity_type": "phone"}'
```

## Adding Custom Modules

Create a new module by extending `BaseOSINTModule`:

```python
from eirescope.modules.base import BaseOSINTModule
from eirescope.core.entity import Entity, EntityType, Investigation

class MyModule(BaseOSINTModule):
    name = "My Custom Module"
    description = "Does something useful"
    supported_entity_types = [EntityType.EMAIL]

    def execute(self, entity: Entity, investigation: Investigation):
        # Your OSINT logic here
        new_entity = Entity(
            entity_type=EntityType.SOCIAL_PROFILE,
            value="https://example.com/profile",
            source_module=self.name,
        )
        investigation.add_entity(new_entity)
        investigation.add_relationship(
            source_id=entity.id,
            target_id=new_entity.id,
            rel_type="found_on",
        )
        return [new_entity]
```

Then register it in `eirescope/core/plugin_manager.py`.

## Irish-Specific Features

- Irish mobile carrier detection (Vodafone, Three, Tesco Mobile)
- Irish landline area code classification (Dublin, Munster, Leinster, etc.)
- VoIP number detection (+353 76 range)
- Premium rate number warnings
- Boards.ie forum profile checking

## Security & Privacy

- All data stored locally (SQLite) — no cloud transmission
- No API keys required for core functionality
- User-agent rotation to avoid fingerprinting
- Rate limiting built into HTTP client
- Reports include legal disclaimers

## Disclaimer

All data is gathered exclusively from publicly available sources. The accuracy of results depends on the reliability of external data sources. All intelligence should be independently verified before use in legal proceedings.

## License

MIT License — See LICENSE file for details.

## Contributing

Contributions welcome. See the project structure above and extend the module system to add new OSINT capabilities. Focus areas:

- Additional social platform checks
- Irish Companies Office (CRO) integration
- Blockchain address lookups
- Enhanced breach database integrations
- Machine learning entity classification
