#!/usr/bin/env python3
"""
Convert igra INI config files to TOML format.

Usage:
    python scripts/convert-ini-to-toml.py artifacts/igra-config.ini
    python scripts/convert-ini-to-toml.py artifacts/igra-config.ini output.toml

Outputs:
    artifacts/igra-config.toml (or specified output path)

See CONFIG_REFACTORING.md for migration details.
"""

import sys
import re
from pathlib import Path
from configparser import ConfigParser
from collections import defaultdict


def parse_ini_with_profiles(ini_path: Path) -> tuple[dict, dict]:
    """
    Parse INI file, separating base config from profiles.

    Profile sections are detected as:
    - [signer-1.service] -> profile "signer-1", section "service"
    - [signer-2.hd] -> profile "signer-2", section "hd"

    But NOT:
    - [hyperlane.domain.42] -> kept as base (dynamic domain config)
    - [service.pskt] -> kept as base (nested section)
    """
    config = ConfigParser(allow_no_value=True, interpolation=None)
    # Preserve case sensitivity
    config.optionxform = str
    config.read(ini_path)

    base = defaultdict(dict)
    profiles = defaultdict(lambda: defaultdict(dict))

    # Known base section prefixes (not profiles)
    base_prefixes = ['hyperlane', 'service', 'layerzero', 'profiles']

    for section in config.sections():
        # Check if this is a profile section
        # Pattern: <profile-name>.<subsection>
        # where profile-name is like "signer-1", "signer-2", "signer", "coordinator-1", etc.
        match = re.match(r'^(signer-?\d*|coordinator-?\d*)\.(.+)$', section)

        if match:
            profile_name = match.group(1)
            subsection = match.group(2)

            # Make sure it's not a base section like hyperlane.domain.42
            is_base_prefix = any(section.startswith(p + '.') for p in base_prefixes)
            if not is_base_prefix:
                for key, value in config.items(section):
                    profiles[profile_name][subsection][key] = value
                continue

        # Regular base section
        for key, value in config.items(section):
            base[section][key] = value

    return dict(base), dict(profiles)


def convert_value(key: str, value: str) -> str:
    """Convert INI value to TOML value with proper typing."""
    value = "" if value is None else value.strip()

    # Numeric conversion FIRST (before boolean, since "0" could match both)
    numeric_fields = [
        'threshold', 'threshold_m', 'threshold_n', 'sig_op_count', 'required_sigs',
        'poll_secs', 'session_timeout_seconds', 'session_expiry_seconds',
        'min_amount_sompi', 'max_amount_sompi', 'max_daily_volume_sompi',
        'fee_sompi', 'fee_rate_sompi_per_gram', 'test_amount_sompi',
        'finality_blue_score_threshold', 'dust_threshold_sompi',
        'min_recipient_amount_sompi', 'network_id', 'domain',
        'rate_limit_rps', 'rate_limit_burst', 'bind_port'
    ]

    if key in numeric_fields:
        try:
            int(value)
            return value
        except ValueError:
            pass

    # Boolean conversion (AFTER numeric check)
    boolean_fields = ['test_mode', 'enabled', 'require_reason']
    if key in boolean_fields:
        if value.lower() in ('true', 'yes', 'on', '1'):
            return 'true'
        if value.lower() in ('false', 'no', 'off', '0'):
            return 'false'

    # Array fields (comma or pipe separated)
    array_fields = [
        'source_addresses', 'validators', 'member_pubkeys', 'verifier_keys',
        'endpoint_pubkeys', 'xpubs', 'mnemonics', 'allowed_destinations',
        'bootstrap', 'bootstrap_addrs', 'outputs'
    ]

    if key in array_fields:
        if value == "":
            return '[]'
        # Split by comma or pipe
        items = [item.strip() for item in re.split(r'[,|]', value) if item.strip()]
        if items:
            quoted = [f'"{item}"' for item in items]
            if len(quoted) == 1:
                return f'[{quoted[0]}]'
            # Multi-line for readability
            return '[\n    ' + ',\n    '.join(quoted) + '\n]'
        return '[]'

    if value == "":
        return '""'

    # String (needs quotes)
    # Escape any internal quotes and backslashes
    escaped = value.replace('\\', '\\\\').replace('"', '\\"')
    return f'"{escaped}"'


def section_to_toml(section_name: str, items: dict, indent: str = '') -> list[str]:
    """Convert a section to TOML lines."""
    lines = []

    lines.append(f'{indent}[{section_name}]')

    for key, value in items.items():
        toml_value = convert_value(key, value)
        if '\n' in toml_value:
            # Multi-line array
            lines.append(f'{indent}{key} = {toml_value}')
        else:
            lines.append(f'{indent}{key} = {toml_value}')

    lines.append('')
    return lines


def convert_hyperlane_domains(base: dict) -> list[str]:
    """Convert hyperlane.domain.N sections to [[hyperlane.domains]] array."""
    lines = []
    domains = []

    for section_name in list(base.keys()):
        match = re.match(r'^hyperlane\.domain\.(\d+)$', section_name)
        if match:
            domain_id = match.group(1)
            domain_config = base.pop(section_name)
            domains.append((int(domain_id), domain_config))

    if domains:
        lines.append('# Per-domain ISM configuration')
        for domain_id, config in sorted(domains):
            lines.append('[[hyperlane.domains]]')
            lines.append(f'domain = {domain_id}')
            for key, value in config.items():
                toml_value = convert_value(key, value)
                lines.append(f'{key} = {toml_value}')
            lines.append('')

    return lines


def generate_toml(base: dict, profiles: dict, source_file: str) -> str:
    """Generate TOML content from parsed config."""
    lines = [
        '# =============================================================================',
        '# Igra Configuration (TOML)',
        '# =============================================================================',
        f'# Converted from: {source_file}',
        '# See CONFIG_REFACTORING.md for migration details',
        '#',
        '# Environment variable required:',
        '#   export KASPA_IGRA_WALLET_SECRET=<your-wallet-secret>',
        '',
    ]

    # Define section order for clean output
    section_order = [
        'service',
        'pskt',      # Will be nested under service
        'hd',        # Will be nested under service
        'runtime',
        'signing',
        'rpc',
        'policy',
        'group',
        'hyperlane',
        'layerzero',
        'iroh'
    ]

    # Track written sections
    written = set()

    # Write base sections in order
    for section in section_order:
        if section in base:
            # Handle pskt -> service.pskt renaming
            if section == 'pskt':
                lines.extend(section_to_toml('service.pskt', base[section]))
            elif section == 'hd':
                lines.extend(section_to_toml('service.hd', base[section]))
            else:
                lines.extend(section_to_toml(section, base[section]))
            written.add(section)

    # Write hyperlane domains (before remaining sections)
    domain_lines = convert_hyperlane_domains(base)
    if domain_lines:
        lines.extend(domain_lines)

    # Write remaining sections (e.g., service.pskt if in base)
    for section in sorted(base.keys()):
        if section not in written and not section.startswith('hyperlane.domain.'):
            lines.extend(section_to_toml(section, base[section]))

    # Write profiles
    if profiles:
        lines.append('# =============================================================================')
        lines.append('# Signer Profiles')
        lines.append('# =============================================================================')
        lines.append('# Use --profile <name> to load a specific profile')
        lines.append('# Example: igra-service --profile signer-1')
        lines.append('')

        for profile_name in sorted(profiles.keys()):
            profile_sections = profiles[profile_name]

            lines.append(f'[profiles.{profile_name}]')
            lines.append('')

            # Order subsections consistently
            subsection_order = ['service', 'hd', 'rpc', 'iroh', 'runtime', 'signing']

            for subsection in subsection_order:
                if subsection in profile_sections:
                    items = profile_sections[subsection]
                    lines.append(f'[profiles.{profile_name}.{subsection}]')
                    for key, value in items.items():
                        toml_value = convert_value(key, value)
                        lines.append(f'{key} = {toml_value}')
                    lines.append('')

            # Write any remaining subsections
            for subsection in sorted(profile_sections.keys()):
                if subsection not in subsection_order:
                    items = profile_sections[subsection]
                    lines.append(f'[profiles.{profile_name}.{subsection}]')
                    for key, value in items.items():
                        toml_value = convert_value(key, value)
                        lines.append(f'{key} = {toml_value}')
                    lines.append('')

    return '\n'.join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python convert-ini-to-toml.py <input.ini> [output.toml]")
        print()
        print("Examples:")
        print("  python scripts/convert-ini-to-toml.py artifacts/igra-config.ini")
        print("  python scripts/convert-ini-to-toml.py artifacts/igra-prod.ini prod.toml")
        sys.exit(1)

    ini_path = Path(sys.argv[1])
    if not ini_path.exists():
        print(f"Error: {ini_path} not found")
        sys.exit(1)

    toml_path = Path(sys.argv[2]) if len(sys.argv) > 2 else ini_path.with_suffix('.toml')

    print(f"Converting: {ini_path}")
    print(f"Output:     {toml_path}")
    print()

    base, profiles = parse_ini_with_profiles(ini_path)

    print(f"Base sections found: {len(base)}")
    for section in sorted(base.keys()):
        print(f"  - [{section}] ({len(base[section])} keys)")

    if profiles:
        print(f"\nProfiles found: {len(profiles)}")
        for profile in sorted(profiles.keys()):
            sections = list(profiles[profile].keys())
            print(f"  - {profile}: {sections}")

    toml_content = generate_toml(base, profiles, ini_path.name)

    toml_path.write_text(toml_content)
    print(f"\nWritten: {toml_path}")

    # Validate the output
    try:
        import tomllib
        tomllib.loads(toml_content)
        print("Validation: TOML syntax is valid")
    except ImportError:
        try:
            import tomli
            tomli.loads(toml_content)
            print("Validation: TOML syntax is valid")
        except ImportError:
            print("Validation: Skipped (install tomllib/tomli to validate)")
    except Exception as e:
        print(f"Validation: FAILED - {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
