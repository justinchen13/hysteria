"""Bounded H1 evidence state. This does not estimate people or failure rates."""
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import time

MAX_STATE = 256 * 1024
MAX_SESSIONS, MAX_STREAMS, MAX_CLOSES, MAX_MANAGERS = 128, 128, 32, 4
FRESH_SECONDS = 30
EVENTS = {'authenticated', 'sample', 'closed', 'stream_sample', 'stream_closed', 'stream_operation_slow_complete', 'udp_operation_slow_complete', 'stream_terminal_update'}
CLOSE_CLASSES = {'idle_timeout', 'handshake_timeout', 'application', 'transport', 'stateless_reset', 'closed', 'other'}
PHASES = {'initial', 'read', 'accounting', 'write', 'finished'}
ERROR_CLASSES = {'none', 'eof', 'traffic_denied', 'closed', 'timeout', 'other'}
SERVER_COUNTERS = ('dropped_events_total', 'untracked_connections_total')
SESSION_COUNTERS = ('received_packets', 'received_bytes', 'sent_packets', 'sent_bytes',
                    'acknowledged_packets', 'lost_packets', 'time_threshold_losses',
                    'reordering_threshold_losses', 'pto_positive_updates')
UDP_PHASES = {'receive_accounting', 'send_accounting', 'send_datagram', 'feed', 'init', 'target_write'}
UDP_COUNTERS = ('received_datagrams', 'received_payload_bytes', 'parse_errors', 'target_read_datagrams',
                'target_read_bytes', 'target_read_errors', 'target_write_calls', 'target_written_bytes',
                'target_write_errors', 'defrag_pending', 'send_attempts', 'enqueued_datagrams',
                'enqueued_payload_bytes', 'send_too_large', 'send_errors', 'serialize_drops',
                'fragmented_messages', 'fragments_attempted', 'untracked_operations_total')
UDP_SIZE_GAUGES = ('last_too_large_max_datagram_payload_size',
                   'min_too_large_max_datagram_payload_size', 'max_target_read_datagram_size')
UDP_ERROR_PHASES = ('init', 'target_write')
UDP_ERROR_CLASSES = ('dns_timeout', 'dns_not_found', 'dns_other', 'address_invalid',
                     'no_ipv4', 'no_ipv6', 'no_address', 'outbound_mode_invalid',
                     'closed', 'cancelled', 'timeout', 'address_unavailable',
                     'network_unreachable', 'host_unreachable', 'permission_denied',
                     'message_too_large', 'connection_refused', 'would_block', 'no_buffer', 'other')
UDP_ERROR_LAYERS = {'address_parse', 'resolve', 'address_selection', 'socket_write',
                    'connection_state', 'outbound_other'}
PACKET_FIELDS = ('received_packets', 'received_bytes', 'sent_packets', 'sent_bytes',
                 'last_received_age_ms', 'last_sent_age_ms')
APPLICATION_COUNTERS = ('untracked_streams_total', 'fast_path_unobserved_streams_total',
                        'completed_streams_total', 'incomplete_closes_total', 'suppressed_routine_closes_total')
TERMINAL_CLASSES = ('none', 'eof', 'closed', 'traffic_denied', 'timeout', 'other')
QUIC_GAUGES = ('authenticated_age_ms', 'pto_count', 'pto_max', 'latest_rtt_us', 'smoothed_rtt_us',
               'min_rtt_us', 'congestion_window_bytes', 'bytes_in_flight', 'packets_in_flight', 'mtu',
               'last_received_age_ms', 'last_sent_age_ms', 'last_ack_age_ms', 'last_metrics_age_ms')
WAIT_GAUGES = ('pending_bytes', 'writing_streams', 'accounting_streams', 'max_write_age_ms', 'max_accounting_age_ms')
STREAM_COUNTERS = ('read_bytes', 'written_bytes', 'short_writes')
STREAM_GAUGES = ('phase_age_ms', 'pending_bytes', 'max_completed_write_us')
SESSION_PATTERN = r'[a-f0-9]{32}-[a-f0-9]{1,16}'


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def stamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError('invalid timestamp')
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('missing timestamp timezone')
    return parsed.timestamp()


def numeric_fields(source, names, ages=False):
    out = {}
    for name in names:
        value = source.get(name)
        if number(value) and value >= 0:
            out[name] = value
        elif ages and value == -1:
            out[name] = None
    return out


def udp_error_detail(source):
    """Preserve legacy evidence if this optional, separately versioned group is unknown."""
    if not isinstance(source, dict):
        return {'availability': 'invalid'}
    # These fixed markers also make persisted sanitized snapshots round-trip.
    if source.get('availability') in ('invalid', 'context_evicted'):
        return {'availability': source['availability']}
    version = source.get('version')
    if type(version) is not int or not 0 <= version < 2**31:
        return {'availability': 'invalid'}
    if version != 1:
        return {'version': version, 'availability': 'unsupported'}

    def integer(row, name, low=0, high=2**63-1):
        value = row.get(name)
        if type(value) is not int or not low <= value <= high:
            raise ValueError('invalid UDP error integer')
        return value

    try:
        clean = {'version': 1, 'availability': 'supported',
                 'sequence': integer(source, 'sequence', high=2**64-1),
                 'sample_unix_ms': integer(source, 'sample_unix_ms', low=1),
                 'sample_auth_age_us': integer(source, 'sample_auth_age_us')}
        for flag in ('best_effort', 'post_close_updates_may_be_unpublished'):
            if type(source.get(flag)) is not bool:
                raise ValueError('missing UDP error coverage flag')
            clean[flag] = source[flag]
        cells, latest = source.get('counters'), source.get('latest')
        if not isinstance(cells, list) or len(cells) > 40 or not isinstance(latest, list) or len(latest) > 2:
            raise ValueError('invalid UDP error array bound')
        clean['counters'], clean['latest'] = [], []
        identities = {}
        for cell in cells:
            if not isinstance(cell, dict):
                raise ValueError('invalid UDP error cell')
            phase, category = cell.get('phase'), cell.get('class')
            if phase not in UDP_ERROR_PHASES or category not in UDP_ERROR_CLASSES or (phase, category) in identities:
                raise ValueError('invalid UDP error dimension')
            count = integer(cell, 'count', low=1, high=2**64-1)
            first = integer(cell, 'first_auth_age_us')
            last = integer(cell, 'last_auth_age_us', low=first, high=clean['sample_auth_age_us'])
            row = dict(phase=phase, **{'class': category}, count=count, first_auth_age_us=first, last_auth_age_us=last)
            identities[phase, category] = row
            clean['counters'].append(row)
        if sum(c['count'] for c in clean['counters']) != clean['sequence']:
            raise ValueError('incoherent UDP error sequence')
        seen = set()
        for item in latest:
            if not isinstance(item, dict):
                raise ValueError('invalid UDP error latest')
            phase, category = item.get('phase'), item.get('class')
            if (phase in seen or (phase, category) not in identities or
                    item.get('layer') not in UDP_ERROR_LAYERS or item.get('error_address_family') not in ('ipv4', 'ipv6', 'unknown')):
                raise ValueError('invalid UDP error latest dimension')
            seen.add(phase)
            at = integer(item, 'completed_auth_age_us', high=clean['sample_auth_age_us'])
            if at != max(c['last_auth_age_us'] for (p, _), c in identities.items() if p == phase) or at != identities[phase, category]['last_auth_age_us']:
                raise ValueError('incoherent UDP error latest time')
            duration = item.get('duration_us')
            # -1 is only the persistence validator's representation of null.
            if duration is not None and duration != -1:
                duration = integer(item, 'duration_us')
            else:
                duration = None
            row = {k: item[k] for k in ('phase', 'class', 'layer', 'error_address_family')}
            row.update(completed_auth_age_us=at, duration_us=duration,
                       requested_bytes=integer(item, 'requested_bytes'),
                       written_bytes=integer(item, 'written_bytes', low=-(2**63)))
            for flag in ('udp_entry_closing', 'quic_ended'):
                if type(item.get(flag)) is not bool:
                    raise ValueError('missing UDP error lifetime flag')
                row[flag] = item[flag]
            clean['latest'].append(row)
        if seen != {phase for phase, _ in identities}:
            raise ValueError('incomplete UDP error latest')
        return clean
    except (ValueError, TypeError, KeyError):
        return {'availability': 'invalid'}


def sanitize(raw):
    """A fixed allowlist: never copy error strings, addresses, auth or API IDs."""
    if not isinstance(raw, dict) or raw.get('schema') not in (1, 2) or raw.get('event') not in EVENTS:
        raise ValueError('unsupported H1 evidence')
    session = raw.get('session')
    if not isinstance(session, str) or not re.fullmatch(SESSION_PATTERN, session):
        raise ValueError('invalid anonymous session')
    capture = stamp(raw.get('time'))
    if not number(capture) or capture <= 0:
        raise ValueError('invalid evidence time')
    out = {'schema': raw['schema'], 'event': raw['event'], 'session': session, 'capture_unix': capture}
    out.update(numeric_fields(raw, SESSION_COUNTERS + SERVER_COUNTERS))
    out.update(numeric_fields(raw, QUIC_GAUGES, ages=True))
    if type(raw.get('packet_evidence')) is bool:
        out['packet_evidence'] = raw['packet_evidence']
        if not raw['packet_evidence']:
            # Disabled packet callbacks do not mean zero packets or zero age.
            out.update(dict.fromkeys(PACKET_FIELDS))
    if raw.get('congestion_mode') in ('bbr', 'brutal'):
        out['congestion_mode'] = raw['congestion_mode']
    out.update(numeric_fields(raw, ('negotiated_server_tx_bytes_per_second',)))
    udp = raw.get('udp')
    if isinstance(udp, dict):
        clean = numeric_fields(udp, UDP_COUNTERS)
        # Source lifetime/last-error sizes are context, not poll-window peaks.
        clean.update(numeric_fields(udp, UDP_SIZE_GAUGES, ages=True))
        for flag in ('receive_queue_drops_observable', 'waits_best_effort'):
            if type(udp.get(flag)) is bool:
                clean[flag] = udp[flag]
        if 'error_detail' in udp:
            clean['error_detail'] = udp_error_detail(udp['error_detail'])
        waits = udp.get('waits')
        if waits is not None:
            if not isinstance(waits, list) or len(waits) > 8:
                raise ValueError('invalid UDP waits bound')
            clean['waits'] = []
            for wait in waits:
                if (not isinstance(wait, dict) or wait.get('direction') not in ('to_client', 'to_target') or
                        wait.get('phase') not in UDP_PHASES):
                    raise ValueError('invalid UDP wait')
                clean['waits'].append(dict(numeric_fields(wait, ('age_ms', 'pending_bytes'), ages=True),
                                           direction=wait['direction'], phase=wait['phase']))
        out['udp'] = clean
    if raw.get('close_class') in CLOSE_CLASSES:
        out['close_class'] = raw['close_class']
    out.update(numeric_fields(raw, ('close_code',)))
    if type(raw.get('close_remote')) is bool:
        out['close_remote'] = raw['close_remote']
    app = raw.get('application')
    if isinstance(app, dict):
        clean = numeric_fields(app, ('observed_active_streams',) + APPLICATION_COUNTERS)
        if isinstance(app.get('terminal_directions'), dict):
            clean['terminal_directions'] = numeric_fields(app['terminal_directions'], TERMINAL_CLASSES)
        for direction in ('to_client', 'to_target'):
            if isinstance(app.get(direction), dict):
                clean[direction] = numeric_fields(app[direction], WAIT_GAUGES, ages=True)
        out['application'] = clean
    stream = raw.get('stream')
    if raw['event'] in ('stream_sample', 'stream_closed', 'stream_terminal_update'):
        if not isinstance(stream, dict) or type(stream.get('id')) is not int or not 0 <= stream['id'] < 2**64:
            raise ValueError('missing stream identity')
        clean = {'id': stream['id']}
        clean.update(numeric_fields(stream, ('age_ms',), ages=True))
        if type(stream.get('best_effort')) is bool:
            clean['best_effort'] = stream['best_effort']
        for direction in ('to_client', 'to_target'):
            if not isinstance(stream.get(direction), dict):
                continue
            source = stream[direction]
            data = numeric_fields(source, STREAM_COUNTERS)
            data.update(numeric_fields(source, STREAM_GAUGES, ages=True))
            if source.get('phase') in PHASES:
                data['phase'] = source['phase']
            if source.get('error_class') in ERROR_CLASSES:
                data['error_class'] = source['error_class']
            if type(source.get('finished')) is bool:
                data['finished'] = source['finished']
            clean[direction] = data
        out['stream'] = clean
    if raw['event'] in ('stream_operation_slow_complete', 'udp_operation_slow_complete'):
        is_udp = raw['event'] == 'udp_operation_slow_complete'
        key = 'udp_operation' if is_udp else 'operation'
        operation = raw.get(key)
        if (not isinstance(operation, dict) or operation.get('direction') not in ('to_client', 'to_target') or
                operation.get('phase') not in (UDP_PHASES if is_udp else ('accounting', 'write'))):
            raise ValueError('invalid completed operation')
        if not is_udp and (type(operation.get('stream_id')) is not int or not 0 <= operation['stream_id'] < 2**64):
            raise ValueError('invalid completed stream operation')
        start = stamp(operation.get('started_at'))
        values = numeric_fields(operation, ('duration_us', 'requested_bytes', 'written_bytes'))
        if values.get('duration_us', 0) < 1_000_000:
            raise ValueError('missing completed operation duration')
        out[key] = dict(values, direction=operation['direction'], phase=operation['phase'], started_unix=start)
        if not is_udp:
            out[key]['stream_id'] = operation['stream_id']
        if operation.get('error_class') in ERROR_CLASSES:
            out[key]['error_class'] = operation['error_class']
    return out


def epoch(row):
    values = [row.get('container_id'), row.get('image'), row.get('started_at')]
    patterns = (r'[a-f0-9]{12,64}', r'sha256:[a-f0-9]{64}', r'[0-9TZ:+.\-]{20,40}')
    if not all(isinstance(v, str) and re.fullmatch(p, v) for v, p in zip(values, patterns)):
        return None
    return dict(zip(('container_id', 'image', 'started_at'), values))


def add(mapping, key, value=1):
    mapping[key] = mapping.get(key, 0) + value


def empty_state():
    return {'schema': 1, 'epoch': None, 'coverage_start_unix': None, 'last_poll_unix': None,
            'last_evidence_unix': None, 'gap_generation': 0, 'quality': {}, 'events': {},
            'close_classes': {}, 'operation_phases': {}, 'observed_counter_deltas': {}, 'deltas_spanning_gap': {},
            'counter_resets_or_replays': {}, 'managers': {}, 'sessions': {}, 'streams': {},
            'recent_event_ids': [], 'recent_closes': []}


def valid_clean_snapshot(value):
    # Reuse the allowlist to validate persistence, including nested shapes.
    if not isinstance(value, dict) or not number(value.get('capture_unix')):
        return False
    raw = dict(value, time=dt.datetime.fromtimestamp(value['capture_unix'], dt.timezone.utc).isoformat())
    for key in ('operation', 'udp_operation'):
        if key in raw:
            op = raw[key]
            if not isinstance(op, dict) or not number(op.get('started_unix')):
                return False
            raw[key] = dict(op, started_at=dt.datetime.fromtimestamp(op['started_unix'], dt.timezone.utc).isoformat())
    def restore_unknown(item):
        if isinstance(item, dict):
            return {k: restore_unknown(v) for k, v in item.items()}
        if isinstance(item, list):
            return [restore_unknown(v) for v in item]
        return -1 if item is None else item
    return sanitize(restore_unknown(raw)) == value


def validate_state(state):
    template = empty_state()
    if not isinstance(state, dict) or not template.keys() <= state.keys() or state['schema'] != 1:
        raise ValueError('invalid H1 state')
    if state['epoch'] is not None and epoch(state['epoch']) != state['epoch']:
        raise ValueError('invalid state epoch')
    for key in ('coverage_start_unix', 'last_poll_unix', 'last_evidence_unix'):
        if state[key] is not None and not number(state[key]):
            raise ValueError('invalid state time')
    if type(state['gap_generation']) is not int or state['gap_generation'] < 0:
        raise ValueError('invalid gap generation')
    for key in ('quality', 'events', 'close_classes', 'operation_phases', 'observed_counter_deltas', 'deltas_spanning_gap', 'counter_resets_or_replays'):
        if not isinstance(state[key], dict) or not all(isinstance(k, str) and len(k) <= 128 and number(v) and v >= 0 for k, v in state[key].items()):
            raise ValueError('invalid state counters')
    if not isinstance(state['recent_event_ids'], list) or len(state['recent_event_ids']) > 512 or not all(isinstance(x, str) and re.fullmatch(r'[a-f0-9]{32}', x) for x in state['recent_event_ids']):
        raise ValueError('invalid event identities')
    if not isinstance(state['recent_closes'], list) or len(state['recent_closes']) > MAX_CLOSES or not all(valid_clean_snapshot(x) for x in state['recent_closes']):
        raise ValueError('invalid close examples')
    for group, limit in (('managers', MAX_MANAGERS), ('sessions', MAX_SESSIONS), ('streams', MAX_STREAMS)):
        if not isinstance(state[group], dict) or len(state[group]) > limit:
            raise ValueError('invalid registry')
        for key, entry in state[group].items():
            pattern = r'[a-f0-9]{32}' if group == 'managers' else SESSION_PATTERN + (r'/[0-9]{1,20}' if group == 'streams' else '')
            if not isinstance(key, str) or not re.fullmatch(pattern, key) or not isinstance(entry, dict):
                raise ValueError('invalid registry identity')
            if not all(number(entry.get(k)) and entry[k] >= 0 for k in ('last_seen_unix', 'capture_unix', 'generation')):
                raise ValueError('invalid registry times')
            if not isinstance(entry.get('counters'), dict) or not all(number(v) and v >= 0 for v in entry['counters'].values()):
                raise ValueError('invalid counter baselines')
            if group != 'managers' and (not valid_clean_snapshot(entry.get('snapshot')) or type(entry.get('closed')) is not bool):
                raise ValueError('invalid registry snapshot')
            cursor = entry.get('udp_error_cursor')
            if cursor is not None:
                if (group != 'sessions' or not isinstance(cursor, dict) or
                        set(cursor) != {'sequence', 'sample_unix_ms', 'sample_auth_age_us', 'gap'} or
                        any(type(cursor.get(k)) is not int or cursor[k] < 0 for k in ('sequence', 'sample_unix_ms', 'sample_auth_age_us')) or
                        type(cursor.get('gap')) is not bool):
                    raise ValueError('invalid UDP error cursor')


class EvidenceState:
    def __init__(self, directory, interval=10):
        self.path = Path(directory) / 'evidence-state.json'
        self.interval = interval
        self.state = empty_state()
        self.error = False
        self.restarted = False
        if self.path.exists():
            try:
                if self.path.stat().st_size > MAX_STATE:
                    raise ValueError('oversized state')
                loaded = json.loads(self.path.read_text())
                validate_state(loaded)
                self.state = loaded
                self.restarted = True
            except (OSError, ValueError, TypeError, KeyError, OverflowError):
                # Keep a bounded diagnostic fragment; never replay raw logs.
                try:
                    with self.path.open('rb') as source:
                        self.path.with_name('evidence-state.unreadable.json').write_bytes(source.read(MAX_STATE))
                    self.path.with_name('evidence-state.unreadable.json').chmod(0o600)
                except OSError:
                    pass
                self.state['quality']['state_recovery_started_new_segment'] = 1

    def _delta(self, entry, counters, scope, batch, gap):
        for key, value in counters.items():
            name = scope + '.' + key
            before = entry['counters'].get(key)
            if before is None:
                entry['counters'][key] = value
                add(batch['baseline_fields'], name)
            elif value < before:
                # Same random source identity cannot legitimately reset. Preserve
                # the high-water mark to avoid counting a replay twice.
                add(self.state['counter_resets_or_replays'], name)
                add(batch['counter_resets_or_replays'], name)
                add(batch['quality'], 'counter_regression_fields')
            else:
                delta = value - before
                entry['counters'][key] = value
                add(self.state['observed_counter_deltas'], name, delta)
                add(batch['observed_counter_deltas'], name, delta)
                if gap:
                    add(self.state['deltas_spanning_gap'], name, delta)
                    add(batch['deltas_spanning_gap'], name, delta)

    def _entity(self, group, key, counters, clean, now, batch, closed=False):
        registry = self.state[group]
        capture = clean['capture_unix']
        entry = registry.get(key)
        if entry is None:
            limit = {'managers': MAX_MANAGERS, 'sessions': MAX_SESSIONS, 'streams': MAX_STREAMS}[group]
            if len(registry) >= limit:
                victim = min(registry, key=lambda k: registry[k]['last_seen_unix'])
                del registry[victim]
                add(batch['quality'], group + '_evicted')
            entry = {'last_seen_unix': now, 'capture_unix': capture, 'generation': self.state['gap_generation'], 'counters': {}}
            registry[key] = entry
        elif group != 'managers' and capture < entry['capture_unix']:
            add(batch['quality'], 'out_of_order_' + group + '_snapshots')
            # The producer stamps the outer snapshot before taking the
            # independent UDP-error lock. An older outer can therefore carry
            # a newer coherent error snapshot after concurrent enqueueing.
            # Keep legacy counters/time/closed state, and let the error cursor
            # alone decide whether this optional group can advance.
            if group == 'sessions' and self._udp_errors(entry, clean, now, batch, True):
                snapshot = entry['snapshot']
                entry['snapshot'] = dict(snapshot, udp=dict(snapshot.get('udp', {}),
                    error_detail=clean['udp']['error_detail']))
                entry['last_seen_unix'] = now
                add(batch['udp_error_detail']['snapshot_outcomes'], 'accepted_from_older_outer')
            return
        gap = entry['generation'] != self.state['gap_generation'] or capture - entry['capture_unix'] > FRESH_SECONDS
        self._delta(entry, counters, group, batch, gap)
        detail_accepted = None
        if group == 'sessions':
            detail_accepted = self._udp_errors(entry, clean, now, batch, gap)
        entry.update(last_seen_unix=now, capture_unix=max(capture, entry['capture_unix']), generation=self.state['gap_generation'])
        if group != 'managers':
            snapshot = clean
            if (group == 'sessions' and not detail_accepted and
                    clean.get('udp', {}).get('error_detail', {}).get('availability') == 'supported'):
                # Newer outer time cannot make a rejected independent capture
                # current. Keep the last accepted context (or unknown), while
                # legacy fields advance normally; the rejection is in batch.
                previous = entry.get('snapshot', {}).get('udp', {}).get('error_detail')
                snapshot = dict(clean, udp=dict(clean['udp'],
                    error_detail=previous if previous is not None else {'availability': 'invalid'}))
            entry.update(snapshot=snapshot, closed=closed or entry.get('closed', False))

    def _udp_errors(self, entry, clean, now, batch, gap):
        detail = clean.get('udp', {}).get('error_detail', {})
        status = detail.get('availability', 'unknown')
        report = batch['udp_error_detail']
        add(report['availability'], status)
        cursor = entry.get('udp_error_cursor')
        # A complete v1 cursor proves every absent class was zero. Keep only
        # nonzero baselines, including when loading the earlier dense format.
        for key in list(entry['counters']):
            if key.startswith('udp.error_detail.') and entry['counters'][key] == 0:
                del entry['counters'][key]

        def reject(reason):
            add(report['snapshot_outcomes'], reason)
            add(batch['quality'], 'udp_error_detail_' + reason)
            if cursor is not None:
                cursor['gap'] = True

        if status != 'supported':
            if cursor is not None:
                cursor['gap'] = True
            if status in ('invalid', 'unsupported'):
                reject(status)
            return
        # This group's capture is independent of the enclosing log timestamp.
        captured = detail['sample_unix_ms'] / 1000
        if captured > now:
            reject('future_capture')
            return
        values = {'udp.error_detail.' + phase + '.' + category: 0
                  for phase in UDP_ERROR_PHASES for category in UDP_ERROR_CLASSES}
        for cell in detail['counters']:
            values['udp.error_detail.' + cell['phase'] + '.' + cell['class']] = cell['count']
        if cursor is not None:
            if (detail['sample_unix_ms'] < cursor['sample_unix_ms'] or
                    detail['sample_auth_age_us'] < cursor['sample_auth_age_us']):
                reject('out_of_order_capture')
                return
            regressed = [key for key, value in values.items() if value < entry['counters'].get(key, 0)]
            if detail['sequence'] < cursor['sequence'] or regressed:
                for key in regressed:
                    add(self.state['counter_resets_or_replays'], 'sessions.' + key)
                    add(batch['counter_resets_or_replays'], 'sessions.' + key)
                reject('counter_reset_or_replay')
                return
            if detail['sequence'] == cursor['sequence']:
                if any(value != entry['counters'].get(key, 0) for key, value in values.items()):
                    reject('sequence_conflict')
                    return
                add(report['snapshot_outcomes'], 'unchanged_sequence')
            else:
                add(report['snapshot_outcomes'], 'advanced_sequence')
            gap = gap or cursor['gap'] or captured - cursor['sample_unix_ms'] / 1000 > FRESH_SECONDS
        else:
            add(report['snapshot_outcomes'], 'first_baseline')
            add(batch['baseline_fields'], 'sessions.udp.error_detail.complete_snapshot')
        nonzero = {key: value for key, value in values.items() if value}
        if cursor is not None:
            for key in nonzero:
                # New class after a complete known snapshot is an increase
                # from implicit zero, not a fresh unobserved-history baseline.
                entry['counters'].setdefault(key, 0)
        self._delta(entry, nonzero, 'sessions', batch, gap)
        if entry.get('closed'):
            add(report['snapshot_outcomes'], 'snapshot_after_recorded_close')
        entry['udp_error_cursor'] = {key: detail[key] for key in ('sequence', 'sample_unix_ms', 'sample_auth_age_us')}
        entry['udp_error_cursor']['gap'] = False
        return True

    def _prune(self, batch):
        for group, limit in (('managers', MAX_MANAGERS), ('sessions', MAX_SESSIONS), ('streams', MAX_STREAMS)):
            registry = self.state[group]
            while len(registry) > limit:
                victim = min(registry, key=lambda key: registry[key]['last_seen_unix'])
                del registry[victim]
                add(batch['quality'], group + '_evicted')
        while len(self.state['recent_closes']) > MAX_CLOSES:
            self.state['recent_closes'].pop(0)
            add(batch['quality'], 'close_examples_evicted')
        if len(self.state['recent_event_ids']) > 512:
            add(batch['quality'], 'event_identity_cache_evictions', len(self.state['recent_event_ids']) - 512)
            del self.state['recent_event_ids'][:-512]
        # A hard bound takes precedence over configured registry counts.
        estimated_bytes = len(json.dumps(self.state, separators=(',', ':')))
        while estimated_bytes > MAX_STATE - 4096:
            # New optional display context must not evict older session counter
            # chains first. Keep its independent cursor/nonzero baselines; make
            # lost first/latest descriptions explicit instead of inventing zero.
            contexts = [(entry['capture_unix'], group, key, entry['snapshot'])
                        for group in ('streams', 'sessions') for key, entry in self.state[group].items()
                        if entry['snapshot'].get('udp', {}).get('error_detail', {}).get('availability') == 'supported']
            contexts.extend((snapshot['capture_unix'], 'recent_closes', index, snapshot)
                            for index, snapshot in enumerate(self.state['recent_closes'])
                            if snapshot.get('udp', {}).get('error_detail', {}).get('availability') == 'supported')
            if contexts:
                _, group, key, snapshot = min(contexts, key=lambda item: item[:3])
                detail = snapshot['udp']['error_detail']
                marker = {'availability': 'context_evicted'}
                reduced = dict(snapshot, udp=dict(snapshot['udp'], error_detail=marker))
                if group == 'recent_closes':
                    self.state[group][key] = reduced
                else:
                    self.state[group][key]['snapshot'] = reduced
                estimated_bytes -= len(json.dumps(detail, separators=(',', ':'))) - len(json.dumps(marker, separators=(',', ':')))
                add(batch['quality'], 'udp_error_detail_context_evictions')
                continue
            entries = [(entry['last_seen_unix'], group, key) for group in ('streams', 'sessions') for key, entry in self.state[group].items()]
            if entries:
                _, group, key = min(entries)
                estimated_bytes -= len(json.dumps(self.state[group][key], separators=(',', ':'))) + len(json.dumps(key)) + 2
                del self.state[group][key]
                add(batch['quality'], 'state_byte_limit_evictions')
            elif self.state['recent_closes']:
                removed = self.state['recent_closes'].pop(0)
                estimated_bytes -= len(json.dumps(removed, separators=(',', ':'))) + 1
                add(batch['quality'], 'state_byte_limit_evictions')
            else:
                raise ValueError('state exceeds fixed bound')

    def update(self, metadata, clean_records, log_health, now):
        identity = epoch(metadata)
        if identity is None:
            raise ValueError('unknown container epoch')
        batch = {key: {} for key in ('events', 'captured_in_poll_window_events', 'close_classes', 'observed_counter_deltas',
                                    'deltas_spanning_gap', 'counter_resets_or_replays', 'baseline_fields', 'quality', 'current_gauge_peaks')}
        batch.update(capture_first_unix=None, capture_last_unix=None, poll_start_unix=self.state['last_poll_unix'], poll_end_unix=now,
                     completed_operations={'time_classification': {}, 'direction_phase_counts': {}, 'error_classes': {},
                                           'full_duration_us_max_by_class': {}, 'cross_window_overlap_us_max': None})
        batch['completed_udp_operations'] = {key: (None if value is None else {}) for key, value in batch['completed_operations'].items()}
        batch['udp_error_detail'] = {'availability': {}, 'snapshot_outcomes': {}}
        if self.state['epoch'] != identity:
            previous_quality = self.state['quality']
            changed = self.state['epoch'] is not None
            self.state = empty_state()
            self.state.update(epoch=identity, coverage_start_unix=now)
            self.state['quality'].update(previous_quality)
            if changed:
                add(batch['quality'], 'container_epoch_changed')
            batch['poll_start_unix'] = None
        last = self.state['last_poll_unix']
        if last is not None and now <= last:
            raise ValueError('non-increasing collector clock')
        for flag in ('initial_seek_to_end', 'rotation_gap_possible', 'copytruncate_detected'):
            if log_health.get(flag):
                add(batch['quality'], flag)
        if log_health.get('backlog_bytes', 0) > 0:
            add(batch['quality'], 'log_backlog')
        for flag in ('h1_records_truncated', 'h1_invalid_records'):
            if log_health.get(flag, 0):
                add(batch['quality'], flag, log_health[flag])
        if self.restarted:
            add(batch['quality'], 'collector_restart_boundary')
        if self.error:
            add(batch['quality'], 'previous_evidence_update_error')
        if last is not None and now - last > self.interval * 1.5:
            add(batch['quality'], 'collector_sampling_gap')
        if metadata.get('issues'):
            add(batch['quality'], 'collector_issue_sample')
        if batch['quality']:
            self.state['gap_generation'] += 1
        seen = set(self.state['recent_event_ids'])
        for clean in clean_records:
            capture = clean['capture_unix']
            if capture > now:
                add(batch['quality'], 'future_capture_records')
                continue
            sid, event = clean['session'], clean['event']
            identity_fields = [sid, event, capture, clean.get('stream', {}).get('id'), clean.get('operation')]
            if 'udp_operation' in clean:
                identity_fields.append(clean['udp_operation'])
            detail = clean.get('udp', {}).get('error_detail')
            if detail is not None:
                identity_fields.append(detail)
            event_id = hashlib.sha256(json.dumps(identity_fields, sort_keys=True).encode()).hexdigest()[:32]
            if event_id in seen:
                add(batch['quality'], 'duplicate_evidence_records')
                continue
            seen.add(event_id)
            self.state['recent_event_ids'].append(event_id)
            for target in (self.state['events'], batch['events']):
                add(target, event)
            if last is not None and last <= capture <= now:
                add(batch['captured_in_poll_window_events'], event)
            batch['capture_first_unix'] = min(batch['capture_first_unix'], capture) if batch['capture_first_unix'] is not None else capture
            batch['capture_last_unix'] = max(batch['capture_last_unix'], capture) if batch['capture_last_unix'] is not None else capture
            self.state['last_evidence_unix'] = max(self.state['last_evidence_unix'] or capture, capture)
            self._entity('managers', sid.split('-', 1)[0], numeric_fields(clean, SERVER_COUNTERS), clean, now, batch)
            counters = numeric_fields(clean, SESSION_COUNTERS)
            counters.update({'application.' + k: v for k, v in numeric_fields(clean.get('application', {}), APPLICATION_COUNTERS).items()})
            counters.update({'application.terminal_directions.' + k: v for k, v in numeric_fields(clean.get('application', {}).get('terminal_directions', {}), TERMINAL_CLASSES).items()})
            counters.update({'udp.' + k: v for k, v in numeric_fields(clean.get('udp', {}), UDP_COUNTERS).items()})
            # Connection snapshots also accompany stream events; count each
            # monotonic difference once, not each repeated lifetime value.
            already_closed = self.state['sessions'].get(sid, {}).get('closed', False)
            self._entity('sessions', sid, counters, clean, now, batch, event == 'closed')
            if 'stream' in clean:
                stream = clean['stream']
                counters = {direction + '.' + k: v for direction in ('to_client', 'to_target') for k, v in numeric_fields(stream.get(direction, {}), STREAM_COUNTERS).items()}
                self._entity('streams', sid + '/' + str(stream['id']), counters, clean, now, batch, event in ('stream_closed', 'stream_terminal_update'))
            if event in ('closed', 'stream_closed'):
                if event == 'closed' and not already_closed:
                    category = clean.get('close_class', 'unknown')
                    add(self.state['close_classes'], category)
                    add(batch['close_classes'], category)
                elif event == 'closed':
                    add(batch['quality'], 'repeated_retained_session_close')
                self.state['recent_closes'].append(clean)
            for operation_key in ('operation', 'udp_operation'):
                if operation_key not in clean:
                    continue
                operation = clean[operation_key]
                start = operation['started_unix']
                end = start + operation['duration_us'] / 1e6
                category = ('unknown_operation_clock' if start <= 0 or end > capture+.001 else
                            'unknown_poll_start' if last is None else 'before_poll_window' if end <= last else
                            'after_poll_window' if start >= now else 'within_poll_window' if start >= last and end <= now else 'crosses_poll_window')
                is_udp = operation_key == 'udp_operation'
                complete = batch['completed_udp_operations' if is_udp else 'completed_operations']
                phase = operation['direction'] + '.' + operation['phase']
                add(self.state['operation_phases'], ('udp.' if is_udp else '') + phase)
                add(complete['direction_phase_counts'], phase)
                add(complete['error_classes'], operation.get('error_class', 'unknown'))
                add(complete['time_classification'], category)
                complete['full_duration_us_max_by_class'][category] = max(complete['full_duration_us_max_by_class'].get(category, 0), operation['duration_us'])
                if category == 'crosses_poll_window':
                    overlap = max(0, min(end, now)-max(start, last))*1e6
                    complete['cross_window_overlap_us_max'] = max(complete['cross_window_overlap_us_max'] or 0, overlap)
            if now - capture <= FRESH_SECONDS and last is not None and capture >= last:
                values = numeric_fields(clean, ('latest_rtt_us', 'smoothed_rtt_us', 'bytes_in_flight', 'pto_count'))
                for direction in ('to_client', 'to_target'):
                    values.update({'application.' + direction + '.' + k: v for k, v in numeric_fields(clean.get('application', {}).get(direction, {}), WAIT_GAUGES).items()})
                if 'waits' in clean.get('udp', {}):
                    values['udp.observed_wait_slots'] = len(clean['udp']['waits'])
                for wait in clean.get('udp', {}).get('waits', []):
                    prefix = 'udp.' + wait['direction'] + '.' + wait['phase'] + '.'
                    for key, value in numeric_fields(wait, ('age_ms', 'pending_bytes')).items():
                        name = prefix + key
                        values[name] = max(values.get(name, 0), value)
                for key, value in values.items():
                    batch['current_gauge_peaks'][key] = max(batch['current_gauge_peaks'].get(key, 0), value)
        self._prune(batch)
        for key, value in batch['quality'].items():
            add(self.state['quality'], key, value)
        if any(batch['quality'].get(key) for key in ('counter_regression_fields', 'future_capture_records',
                                                   'out_of_order_sessions_snapshots', 'out_of_order_streams_snapshots')):
            self.state['gap_generation'] += 1
        self.state['last_poll_unix'] = now
        encoded = json.dumps(self.state, separators=(',', ':'), allow_nan=False).encode()
        if len(encoded) > MAX_STATE:
            raise ValueError('state exceeds size bound')
        temporary = self.path.with_suffix('.json.tmp')
        with temporary.open('wb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(self.path)
        self.restarted = False
        self.error = False
        observed = self.state['last_evidence_unix'] is not None
        return {'schema': 1, 'status': 'observed' if observed else 'unknown',
                'availability': 'h1_observed' if observed else 'unsupported_or_not_yet_observed',
                'coverage_start_unix': self.state['coverage_start_unix'], 'last_evidence_unix': self.state['last_evidence_unix'],
                'latest_evidence_age_seconds': now - self.state['last_evidence_unix'] if observed else None,
                'freshness_limit_seconds': FRESH_SECONDS, 'batch': batch,
                'retained_sessions': len(self.state['sessions']) if observed else None,
                'retained_streams': len(self.state['streams']) if observed else None,
                'fresh_open_session_snapshots': sum(not e['closed'] and now-e['capture_unix'] <= FRESH_SECONDS for e in self.state['sessions'].values()) if observed else None,
                'stale_open_session_snapshots': sum(not e['closed'] and now-e['capture_unix'] > FRESH_SECONDS for e in self.state['sessions'].values()) if observed else None,
                'state_quality': self.state['quality'], 'shared_24h_rollup_includes_h1': False,
                'udp_error_detail': {'availability': 'baseline_retained' if any('udp_error_cursor' in e for e in self.state['sessions'].values()) else 'unknown',
                                     'retained_sessions_with_baseline': sum('udp_error_cursor' in e for e in self.state['sessions'].values()),
                                     'fresh_supported_open_snapshots': sum(not e['closed'] and
                                         e['snapshot'].get('udp', {}).get('error_detail', {}).get('availability') == 'supported' and
                                         0 <= now-e['snapshot']['udp']['error_detail']['sample_unix_ms']/1000 <= FRESH_SECONDS
                                         for e in self.state['sessions'].values()),
                                     'post_close_updates_may_be_unpublished': True,
                                     'counts_are_observed_deltas_not_failure_rate': True},
                'people_count': 'unknown', 'request_failure_rate': 'unknown', 'real_user_vs_probe_attribution': 'unknown'}

    def record(self, metadata, records, log_health, now=None):
        previous = json.loads(json.dumps(self.state))
        restarted = self.restarted
        try:
            return self.update(metadata, records, log_health, time.time() if now is None else now)
        except Exception as error:
            self.state = previous
            self.restarted = restarted
            self.error = True
            print('h1_evidence_update_failed:' + type(error).__name__, file=sys.stderr, flush=True)
            return {'schema': 1, 'status': 'unknown', 'availability': 'evidence_update_failed',
                    'metrics': None, 'shared_24h_rollup_includes_h1': False}
