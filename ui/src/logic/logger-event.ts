import type { LogType } from '../components/create-config/config';

const EVENT_PREFIX = 'IKUSA_EVENT ';
const VALID_NAME_PATTERN = /^[A-Z][A-Za-z0-9_]{2,15}$/;

type CandidateEvent = {
	type: 'candidate';
	identifier: string;
	time: string;
	names: { name: string; offset: number }[];
	hex: string;
	strategy?: string;
};

function is_candidate_event(value: unknown): value is CandidateEvent {
	if (!value || typeof value !== 'object') return false;
	const event = value as Partial<CandidateEvent>;
	return (
		event.type === 'candidate' &&
		typeof event.identifier === 'string' &&
		typeof event.time === 'string' &&
		Array.isArray(event.names) &&
		event.names.length === 5 &&
		event.names.every(
			(name) =>
				typeof name?.name === 'string' &&
				VALID_NAME_PATTERN.test(name.name) &&
				typeof name?.offset === 'number' &&
				Number.isFinite(name.offset)
		) &&
		typeof event.hex === 'string'
	);
}

export function parse_logger_candidate(data: string): LogType | null {
	if (data.startsWith(EVENT_PREFIX)) {
		try {
			const event: unknown = JSON.parse(data.slice(EVENT_PREFIX.length));
			if (!is_candidate_event(event)) return null;
			return {
				identifier: event.identifier,
				time: event.time,
				names: event.names,
				hex: event.hex
			};
		} catch (error) {
			console.error('Invalid logger event', error, data);
			return null;
		}
	}

	// Backwards compatibility with logger builds that still emit CSV-like rows.
	const fields = data.split(',');
	if (fields.length !== 8 || data.includes('Network Interfaces:')) return null;

	return {
		identifier: fields[0],
		time: fields[1],
		names: fields.slice(2, 7).map((name) => {
			const split = name.split(' ');
			return { name: split[0], offset: Number(split[1]) };
		}),
		hex: fields[7]
	};
}

export function is_same_candidate(left: LogType, right: LogType) {
	return (
		left.identifier === right.identifier &&
		left.time === right.time &&
		left.names.length === right.names.length &&
		left.names.every((name, index) => name.name === right.names[index].name)
	);
}

/** Return only the field that the protocol parser validated for this record. */
export function candidate_name_at_index(log: LogType, index: number) {
	return log.names[index]?.name ?? '';
}

/** Read a configured hex nibble after applying this record's layout shift. */
export function candidate_nibble_at_relative_offset(
	log: LogType,
	configured_offset: number,
	anchor_name_index: number,
	configured_anchor_offset: number
) {
	const actual_anchor_offset = log.names[anchor_name_index]?.offset;
	if (actual_anchor_offset === undefined) return '';

	const offset = configured_offset + actual_anchor_offset - configured_anchor_offset;
	return log.hex[offset] ?? '';
}
