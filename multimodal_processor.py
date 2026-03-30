"""
Multimodal Data Processor
Implements the paper's unified data integration mechanism (Section 3.1 - 3.3):
  D = ∪_{k=1}^{S} D_k                     (Equation 1)
  x_i = (x_i1, x_i2, ..., x_im)           (Equation 2)
  X' = P(X)                                (Equation 3)
  x' = (x - µ) / σ                        (Equation 4)
  M = {T1, T2, ..., Tn}                   (Equation 5)
  Sim(Ti, Tj) = Ti·Tj / (||Ti|| ||Tj||)   (Equation 6)
"""

import json
import math
import logging
from typing import Dict, List, Any, Tuple
from datetime import datetime, timedelta
import random

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helper: cosine similarity  (Equation 6)
# ─────────────────────────────────────────────────────────────────────────────
def cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    """
    Sim(Ti, Tj) = Ti · Tj / (||Ti|| ||Tj||)   — Equation (6)
    Returns value in [0, 1].
    """
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a ** 2 for a in vec_a))
    norm_b = math.sqrt(sum(b ** 2 for b in vec_b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def normalize_feature(value: float, mean: float, std: float) -> float:
    """x' = (x - µ) / σ   — Equation (4)"""
    if std == 0:
        return 0.0
    return (value - mean) / std


class MultimodalDataProcessor:
    """
    Implements the paper's unified data integration mechanism.
    Integrates the 5 heterogeneous sources named in Section 1 and 3.1:
      1. System logs
      2. Network traffic statistics
      3. IDS alerts
      4. DNS communication records
      5. Endpoint activities
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.event_cache: List[Dict] = []
        self.correlations: List[Dict] = []
        # For feature normalisation (Eq. 4) — populated during processing
        self._feature_stats: Dict[str, Dict[str, float]] = {}

    # ── Source 1: System Logs ─────────────────────────────────────────────────
    def process_system_logs(self) -> List[Dict]:
        """Simulate / ingest system logs (operating systems and server logs)."""
        # Normal events (80%) vs suspicious events (20%)
        normal_log_events = [
            ('USER_LOGIN',        'low'),
            ('FILE_ACCESS',       'low'),
            ('PROCESS_EXEC',      'low'),
            ('USER_LOGOUT',       'low'),
            ('SERVICE_STOP',      'low'),
            ('SUDO_USAGE',        'low'),
            ('PERMISSION_CHANGE', 'low'),
        ]
        suspicious_log_events = [
            ('AUTH_FAILURE',         'high'),
            ('FAILED_LOGIN',         'high'),
            ('PRIVILEGE_ESCALATION', 'critical'),
        ]
        events = []
        for _ in range(15):
            pool = suspicious_log_events if random.random() < 0.20 else normal_log_events
            event_type, severity = random.choice(pool)
            events.append({
                'source': 'system_logs',
                'timestamp': (datetime.now() - timedelta(minutes=random.randint(0, 60))).isoformat(),
                'event_type': event_type,
                'description': f'{event_type.replace("_", " ").title()} detected',
                'user': f'user{random.randint(1, 20)}',
                'source_host': f'host-{random.randint(1, 50)}',
                'source_ip': f'192.168.1.{random.randint(1, 254)}',
                'severity': severity,
                # Raw features for Equation (2)
                'features': {
                    'f_severity_numeric': {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}[severity],
                    'f_is_auth_event': 1 if 'AUTH' in event_type or 'LOGIN' in event_type else 0,
                    'f_is_privilege_event': 1 if 'PRIVILEGE' in event_type or 'SUDO' in event_type else 0,
                },
            })
        logger.info(f"[Source 1] Processed {len(events)} system log events")
        return events

    # ── Source 2: Network Traffic Statistics ─────────────────────────────────
    def process_network_traffic(self) -> List[Dict]:
        """Simulate / ingest network traffic statistics."""
        events = []
        for _ in range(20):
            bytes_sent = random.randint(100, 5_000_000)
            packet_count = random.randint(10, 50_000)
            duration = random.randint(1, 3600)
            # Malicious ports (4444=Metasploit, 31337=elite backdoor) included at low rate (~10%)
            # so the network-traffic signal in _count_suspicion_signals can fire correctly.
            dest_port = random.choices(
                [22, 80, 443, 53, 3306, 5432, 8080, 8443, 4444, 31337],
                weights=[18, 18, 18, 10, 7, 7, 7, 7, 4, 4], k=1
            )[0]
            is_suspicious_port = dest_port not in [22, 80, 443, 53, 3306, 5432]
            events.append({
                'source': 'network_traffic',
                'timestamp': (datetime.now() - timedelta(minutes=random.randint(0, 60))).isoformat(),
                'source_ip': f'192.168.1.{random.randint(1, 254)}',
                'dest_ip': f'10.0.0.{random.randint(1, 254)}',
                'source_port': random.randint(1024, 65535),
                'dest_port': dest_port,
                'protocol': random.choice(['TCP', 'UDP']),
                'bytes_sent': bytes_sent,
                'bytes_received': random.randint(100, 1_000_000),
                'packet_count': packet_count,
                'duration_sec': duration,
                'flags': random.choice(['SYN', 'ACK', 'RST', 'FIN', 'SYN-ACK']),
                # Raw features for Equation (2)
                'features': {
                    'f_bytes_sent': bytes_sent,
                    'f_packet_count': packet_count,
                    'f_duration': duration,
                    'f_dest_port': dest_port,
                    'f_is_suspicious_port': int(is_suspicious_port),
                    'f_bytes_per_packet': bytes_sent / max(packet_count, 1),
                },
            })
        logger.info(f"[Source 2] Processed {len(events)} network traffic events")
        return events

    # ── Source 3: IDS Alerts ──────────────────────────────────────────────────
    def process_ids_alerts(self) -> List[Dict]:
        """Simulate / ingest Intrusion Detection System alerts."""
        # Normal IDS noise (75%) vs real threat alerts (25%)
        normal_ids = [
            ('Port Scanning Detected',      'low'),
            ('Suspicious Payload',          'low'),
            ('Cross-Site Scripting (XSS)',  'low'),
            ('Directory Traversal',         'low'),
        ]
        threat_ids = [
            ('Buffer Overflow Attempt',     'critical'),
            ('Malware Signature Match',     'critical'),
            ('SQL Injection Attempt',       'high'),
            ('Command Injection',           'critical'),
            ('Brute Force Authentication',  'high'),
        ]
        events = []
        for _ in range(10):
            pool = threat_ids if random.random() < 0.25 else normal_ids
            alert_type, severity = random.choice(pool)
            events.append({
                'source': 'ids_alerts',
                'timestamp': (datetime.now() - timedelta(minutes=random.randint(0, 60))).isoformat(),
                'alert_type': alert_type,
                'source_ip': f'192.168.1.{random.randint(1, 254)}',
                'dest_ip': f'10.0.0.{random.randint(1, 254)}',
                'signature_id': f'SID-{random.randint(1_000_000, 9_999_999)}',
                'severity': severity,
                'protocol': random.choice(['TCP', 'UDP']),
                'payload_summary': 'Suspicious payload detected',
                # Raw features for Equation (2)
                'features': {
                    'f_severity_numeric': {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}[severity],
                    'f_is_injection': 1 if 'Injection' in alert_type else 0,
                    'f_is_overflow': 1 if 'Overflow' in alert_type else 0,
                    'f_is_scanning': 1 if 'Scanning' in alert_type else 0,
                },
            })
        logger.info(f"[Source 3] Processed {len(events)} IDS alerts")
        return events

    # ── Source 4: DNS Communication Records ──────────────────────────────────
    def process_dns_records(self) -> List[Dict]:
        """Simulate / ingest DNS communication records."""
        suspicious_domains = [
            'malware-c2.ru', 'botnet-ctrl.xyz', 'phish-login.net',
            'data-exfil.io', 'dga-abc123.com',
        ]
        normal_domains = [
            'google.com', 'microsoft.com', 'github.com',
            'amazon.com', 'cloudflare.com',
        ]
        events = []
        for _ in range(15):
            is_suspicious = random.random() < 0.15  # Reduced: normal traffic has few suspicious domains
            domain = random.choice(suspicious_domains if is_suspicious else normal_domains)
            query_count = random.randint(1, 200)
            response_code = random.choice(['NOERROR', 'NXDOMAIN', 'SERVFAIL'])
            events.append({
                'source': 'dns_records',
                'timestamp': (datetime.now() - timedelta(minutes=random.randint(0, 60))).isoformat(),
                'query_ip': f'192.168.1.{random.randint(1, 254)}',
                'domain': domain,
                'record_type': random.choice(['A', 'AAAA', 'MX', 'TXT', 'CNAME']),
                'response_code': response_code,
                'response_ip': f'1.1.1.{random.randint(1, 254)}',
                'is_suspicious': is_suspicious,
                'query_count': query_count,
                # Raw features for Equation (2)
                'features': {
                    'f_is_suspicious_domain': int(is_suspicious),
                    'f_query_count': query_count,
                    'f_domain_length': len(domain),
                    'f_is_nxdomain': 1 if response_code == 'NXDOMAIN' else 0,  # FIX: use actual response_code
                },
            })
        logger.info(f"[Source 4] Processed {len(events)} DNS records")
        return events

    # ── Source 5: Endpoint Activities ────────────────────────────────────────
    def process_endpoint_activity(self) -> List[Dict]:
        """Simulate / ingest endpoint activity logs."""
        activity_types = [
            ('File Download',       'low'),
            ('Process Creation',    'medium'),
            ('Registry Change',     'high'),
            ('Network Connection',  'medium'),
            ('Service Install',     'high'),
            ('Scheduled Task',      'medium'),
            ('WMI Event',           'high'),
            ('Driver Loaded',       'critical'),
            ('Credential Access',   'critical'),
        ]
        events = []
        for _ in range(12):
            activity_type, severity = random.choice(activity_types)
            process_name = random.choice(['svchost.exe', 'powershell.exe', 'cmd.exe', 'wscript.exe'])
            # activity_type_key: snake_case version used by _count_suspicion_signals keyword matching
            activity_type_key = activity_type.lower().replace(' ', '_')
            events.append({
                'source': 'endpoint_activity',
                'timestamp': (datetime.now() - timedelta(minutes=random.randint(0, 60))).isoformat(),
                'endpoint_id': f'endpoint-{random.randint(1, 100)}',
                'activity_type': activity_type,
                'activity_type_key': activity_type_key,   # FIX: snake_case for signal matching
                'user': f'user{random.randint(1, 20)}',
                'process_name': process_name,
                'process_id': random.randint(100, 10000),
                'file_path': f'C:\\Users\\User{random.randint(1,5)}\\AppData\\...',
                'command_line': 'Encoded command execution detected',
                'severity': severity,
                # Raw features for Equation (2)
                'features': {
                    'f_severity_numeric': {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}[severity],
                    'f_is_powershell': 1 if 'powershell' in process_name.lower() else 0,  # FIX: check actual variable
                    'f_is_registry': 1 if 'Registry' in activity_type else 0,
                    'f_is_credential': 1 if 'Credential' in activity_type else 0,
                },
            })
        logger.info(f"[Source 5] Processed {len(events)} endpoint activity events")
        return events

    # ── Preprocessing  X' = P(X)  (Equation 3 & 4) ───────────────────────────
    def preprocess_events(self, events: List[Dict]) -> List[Dict]:
        """
        Preprocessing stage — Equation (3): X' = P(X)
        - Removes duplicates / nulls
        - Normalises numeric features: x' = (x - µ) / σ  (Equation 4)
        - Aligns timestamps
        """
        # Collect all numeric feature values for computing µ and σ
        feature_values: Dict[str, List[float]] = {}
        for ev in events:
            for feat_name, feat_val in ev.get('features', {}).items():
                feature_values.setdefault(feat_name, []).append(float(feat_val))

        # Compute µ and σ per feature
        feature_stats: Dict[str, Dict[str, float]] = {}
        for feat_name, vals in feature_values.items():
            mean = sum(vals) / len(vals)
            std = math.sqrt(sum((v - mean) ** 2 for v in vals) / max(len(vals) - 1, 1))
            feature_stats[feat_name] = {'mean': mean, 'std': std}
        self._feature_stats = feature_stats

        # Apply normalisation to each event
        cleaned: List[Dict] = []
        seen_keys = set()
        for ev in events:
            # Deduplication: skip exact duplicate (source, timestamp, event_type/alert_type)
            key = (ev.get('source'), ev.get('timestamp'),
                   ev.get('event_type', ev.get('alert_type', ev.get('activity_type', ''))))
            if key in seen_keys:
                continue
            seen_keys.add(key)

            # Normalise features
            normalised_features = {}
            for feat_name, feat_val in ev.get('features', {}).items():
                stats = feature_stats.get(feat_name, {'mean': 0, 'std': 1})
                normalised_features[feat_name + '_norm'] = round(
                    normalize_feature(float(feat_val), stats['mean'], stats['std']), 4
                )
            ev['normalised_features'] = normalised_features
            cleaned.append(ev)

        logger.info(f"[Preprocessing] {len(events)} → {len(cleaned)} events after cleaning & normalisation")
        return cleaned

    # ── Multimodal Data Representation  M = {T1, …, Tn}  (Equation 5) ────────
    def build_textual_representations(self, events: List[Dict]) -> List[Dict]:
        """
        Converts each security event into a structured textual description Ti.
        M = {T1, T2, …, Tn}  — Equation (5)
        These texts are the input to the LLM (Section 3.3 of paper).
        """
        representations = []
        for ev in events:
            source = ev.get('source', 'unknown')

            if source == 'system_logs':
                text = (
                    f"[SYSTEM LOG] Event: {ev.get('event_type')} | "
                    f"User: {ev.get('user')} | Host: {ev.get('source_host')} | "
                    f"IP: {ev.get('source_ip')} | Severity: {ev.get('severity')} | "
                    f"Time: {ev.get('timestamp')}"
                )
            elif source == 'network_traffic':
                text = (
                    f"[NETWORK TRAFFIC] {ev.get('source_ip')}:{ev.get('source_port')} → "
                    f"{ev.get('dest_ip')}:{ev.get('dest_port')} | "
                    f"Proto: {ev.get('protocol')} | Bytes: {ev.get('bytes_sent')} | "
                    f"Packets: {ev.get('packet_count')} | Flags: {ev.get('flags')} | "
                    f"Time: {ev.get('timestamp')}"
                )
            elif source == 'ids_alerts':
                text = (
                    f"[IDS ALERT] {ev.get('alert_type')} | "
                    f"Src: {ev.get('source_ip')} → Dst: {ev.get('dest_ip')} | "
                    f"Sig: {ev.get('signature_id')} | Severity: {ev.get('severity')} | "
                    f"Time: {ev.get('timestamp')}"
                )
            elif source == 'dns_records':
                text = (
                    f"[DNS RECORD] Query from {ev.get('query_ip')} for {ev.get('domain')} "
                    f"({ev.get('record_type')}) | Response: {ev.get('response_code')} | "
                    f"Count: {ev.get('query_count')} | Suspicious: {ev.get('is_suspicious')} | "
                    f"Time: {ev.get('timestamp')}"
                )
            elif source == 'endpoint_activity':
                text = (
                    f"[ENDPOINT] {ev.get('activity_type')} on {ev.get('endpoint_id')} | "
                    f"User: {ev.get('user')} | Process: {ev.get('process_name')} "
                    f"(PID {ev.get('process_id')}) | Severity: {ev.get('severity')} | "
                    f"Time: {ev.get('timestamp')}"
                )
            else:
                text = f"[UNKNOWN SOURCE] {json.dumps(ev, default=str)}"

            # Simple bag-of-words style embedding vector (sparse, for Eq. 6 demo)
            vocab_tokens = [
                # auth / credential
                'fail', 'auth', 'credential', 'login', 'password', 'privilege', 'sudo',
                # network / traffic
                'suspicious', 'scan', 'transfer', 'beacon', 'c2', 'port', 'traffic',
                # dns
                'dns', 'domain', 'query', 'nxdomain', 'tunnel',
                # malware / exploit
                'malware', 'injection', 'overflow', 'exploit', 'payload', 'encrypt',
                # threat actions
                'exfil', 'lateral', 'movement', 'persistence', 'escalation',
                # severity / alert
                'critical', 'alert', 'high', 'severe', 'anomaly',
                # endpoint
                'process', 'execution', 'endpoint', 'driver', 'kernel',
            ]
            bow_vector = [1.0 if token in text.lower() else 0.0 for token in vocab_tokens]

            representations.append({
                'event_id': id(ev),
                'source': source,
                'timestamp': ev.get('timestamp'),
                'text': text,
                'embedding_vector': bow_vector,  # Ti used in Eq. 6
                'original_event': ev,
            })
        logger.info(f"[Representation] Built {len(representations)} textual representations")
        return representations

    # ── Cross-Source Correlation  Sim(Ti, Tj) > θ  (Equations 6 & 7) ─────────
    def correlate_events(
        self,
        representations: List[Dict],
        theta: float = 0.4
    ) -> List[Dict]:
        """
        Identifies correlated events across different data sources.
        Uses cosine similarity (Equation 6) and threshold θ (Equation 7).
        Only events from DIFFERENT sources are compared (cross-source correlation).
        """
        correlations = []
        n = len(representations)
        for i in range(n):
            for j in range(i + 1, n):
                ri, rj = representations[i], representations[j]
                # Cross-source only
                if ri['source'] == rj['source']:
                    continue
                sim = cosine_similarity(ri['embedding_vector'], rj['embedding_vector'])
                if sim > theta:
                    correlations.append({
                        'timestamp': datetime.now().isoformat(),
                        'event_i': ri['text'][:100],
                        'event_j': rj['text'][:100],
                        'source_i': ri['source'],
                        'source_j': rj['source'],
                        'similarity_score': round(sim, 4),
                        'description': (
                            f"Cross-source correlation detected between "
                            f"{ri['source']} and {rj['source']} "
                            f"(similarity={sim:.3f} > θ={theta})"
                        ),
                    })
        logger.info(
            f"[Correlation] Found {len(correlations)} cross-source correlations "
            f"(θ={theta})"
        )
        return correlations

    # ── Load from uploaded dataset (CSV or JSON) ─────────────────────────────
    def load_from_dataset(self, file_content: str, file_type: str) -> Dict[str, List[Dict]]:
        """
        Parse an uploaded CSV or JSON dataset into the 5 source buckets.

        Supported formats:
        ─────────────────
        JSON  — either:
          • A dict with keys: system_logs, network_traffic, ids_alerts,
                               dns_records, endpoint_activity  (each a list)
          • A flat list of event dicts, each with a 'source' field

        CSV   — one row per event with at least a 'source' column.
                Extra columns become the event fields automatically.
                Recognised source values (case-insensitive):
                  system_logs / syslog / log
                  network_traffic / network / traffic
                  ids_alerts / ids / alert
                  dns_records / dns
                  endpoint_activity / endpoint
        """
        import io
        SOURCES = ['system_logs', 'network_traffic', 'ids_alerts',
                   'dns_records', 'endpoint_activity']

        SOURCE_ALIASES = {
            'system_logs': ['system_logs', 'syslog', 'log', 'system log'],
            'network_traffic': ['network_traffic', 'network', 'traffic', 'net'],
            'ids_alerts': ['ids_alerts', 'ids', 'alert', 'ids alert'],
            'dns_records': ['dns_records', 'dns', 'dns record'],
            'endpoint_activity': ['endpoint_activity', 'endpoint', 'edr'],
        }

        def resolve_source(raw: str) -> str:
            r = raw.strip().lower().replace('-', '_').replace(' ', '_')
            for canonical, aliases in SOURCE_ALIASES.items():
                if r in [a.replace(' ', '_') for a in aliases]:
                    return canonical
            return 'system_logs'  # default bucket

        def enrich(ev: Dict, source: str) -> Dict:
            """Add required fields missing from the dataset row."""
            ev.setdefault('source', source)
            ev.setdefault('timestamp', datetime.now().isoformat())
            ev.setdefault('severity', ev.get('severity', 'low'))
            ev.setdefault('features', {
                'f_severity_numeric': {'low': 1, 'medium': 2,
                                       'high': 3, 'critical': 4}.get(
                    str(ev.get('severity', 'low')).lower(), 1),
            })
            # DNS-specific: normalise is_suspicious to a real bool
            if source == 'dns_records' and 'is_suspicious' in ev:
                val = str(ev['is_suspicious']).strip().lower()
                ev['is_suspicious'] = val in ('true', '1', 'yes')
            return ev

        buckets: Dict[str, List[Dict]] = {s: [] for s in SOURCES}

        try:
            if file_type == 'json':
                data = json.loads(file_content)
                if isinstance(data, dict):
                    # Pre-bucketed format
                    for src in SOURCES:
                        for row in data.get(src, []):
                            if isinstance(row, dict):
                                buckets[src].append(enrich(dict(row), src))
                elif isinstance(data, list):
                    # Flat list — route by 'source' field
                    for row in data:
                        if isinstance(row, dict):
                            src = resolve_source(str(row.get('source', 'system_logs')))
                            buckets[src].append(enrich(dict(row), src))
                else:
                    raise ValueError("JSON must be a dict or a list of dicts.")

            elif file_type == 'csv':
                import csv
                reader = csv.DictReader(io.StringIO(file_content))
                for row in reader:
                    src = resolve_source(str(row.get('source', 'system_logs')))
                    buckets[src].append(enrich(dict(row), src))

            else:
                raise ValueError(f"Unsupported file type: {file_type}. Use 'csv' or 'json'.")

        except Exception as e:
            logger.error(f"[Dataset] Failed to parse uploaded file: {e}")
            raise

        total = sum(len(v) for v in buckets.values())
        logger.info(f"[Dataset] Loaded {total} events from uploaded file "
                    f"({', '.join(f'{s}:{len(buckets[s])}' for s in SOURCES)})")
        return buckets

    # ── Aggregate  D = ∪_{k=1}^{S} Dk  (Equation 1) ─────────────────────────
    def aggregate_all_sources(self, external: Dict[str, List[Dict]] = None) -> Dict[str, Any]:
        """
        Aggregates all S=5 data sources into unified dataset D.
        D = D1 ∪ D2 ∪ D3 ∪ D4 ∪ D5   — Equation (1)

        If `external` is provided (from load_from_dataset), those events are
        used instead of the built-in simulators.  Sources absent in the
        uploaded file fall back to the simulator so all 5 modalities are
        always populated.
        """
        logger.info("Aggregating all 5 security data sources (Equation 1)…")
        ext = external or {}
        raw = {
            'system_logs':       ext.get('system_logs')       or self.process_system_logs(),
            'network_traffic':   ext.get('network_traffic')   or self.process_network_traffic(),
            'ids_alerts':        ext.get('ids_alerts')        or self.process_ids_alerts(),
            'dns_records':       ext.get('dns_records')       or self.process_dns_records(),
            'endpoint_activity': ext.get('endpoint_activity') or self.process_endpoint_activity(),
        }
        all_events = []
        for source_events in raw.values():
            all_events.extend(source_events)

        aggregated = {
            'timestamp': datetime.now().isoformat(),
            'num_sources': 5,
            **raw,
            'total_events': len(all_events),
        }
        logger.info(f"Aggregated {len(all_events)} events from {aggregated['num_sources']} sources")
        return aggregated

    # ── Format for LLM (Section 3.4) ─────────────────────────────────────────
    def format_for_llm(self, representations: List[Dict], correlations: List[Dict]) -> str:
        """
        Formats the structured textual representations M = {T1, …, Tn}
        and correlation findings for LLM consumption (Section 3.4).
        """
        # Sample up to 5 events per source for context window management
        by_source: Dict[str, List[str]] = {}
        for rep in representations:
            by_source.setdefault(rep['source'], []).append(rep['text'])

        llm_payload = {
            'analysis_timestamp': datetime.now().isoformat(),
            'data_sources_integrated': list(by_source.keys()),
            'system_logs':       by_source.get('system_logs', [])[:5],
            'network_traffic':   by_source.get('network_traffic', [])[:5],
            'ids_alerts':        by_source.get('ids_alerts', [])[:5],
            'dns_records':       by_source.get('dns_records', [])[:5],
            'endpoint_activity': by_source.get('endpoint_activity', [])[:5],
            'cross_source_correlations': [
                c['description'] for c in correlations[:10]
            ],
        }
        return json.dumps(llm_payload, indent=2, default=str)

    # ── Main pipeline entry point ─────────────────────────────────────────────
    def process_all(self, external: Dict[str, List[Dict]] = None) -> Dict[str, Any]:
        """
        Execute the complete multimodal data processing pipeline
        (Sections 3.1 → 3.3 of the paper).

        Pass `external` (from load_from_dataset) to use an uploaded dataset
        instead of the built-in simulators.
        """
        logger.info("=== Starting complete multimodal data processing pipeline ===")

        # Step 1 — Data Acquisition (Section 3.1, Equation 1)
        aggregated = self.aggregate_all_sources(external=external)

        # Flatten all events for preprocessing
        all_events = []
        for key in ['system_logs', 'network_traffic', 'ids_alerts', 'dns_records', 'endpoint_activity']:
            all_events.extend(aggregated.get(key, []))

        # Step 2 — Preprocessing (Section 3.2, Equations 3 & 4)
        cleaned_events = self.preprocess_events(all_events)

        # Step 3 — Multimodal Representation (Section 3.3, Equation 5)
        representations = self.build_textual_representations(cleaned_events)

        # Step 4 — Cross-source Correlation (Equations 6 & 7)
        theta = 0.65  # Higher threshold: only strong correlations count as a signal
        correlations = self.correlate_events(representations, theta=theta)

        # Step 5 — Format for LLM
        llm_input = self.format_for_llm(representations, correlations)

        return {
            'aggregated_data': aggregated,
            'cleaned_events': cleaned_events,
            'representations': representations,
            'correlations': correlations,
            'llm_input': llm_input,
        }