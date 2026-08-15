import type { LogType } from '../components/create-config/config';

const EVENT_PREFIX = 'IKUSA_EVENT ';

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
		event.names.length >= 3 &&
		event.names.every(
			(name) =>
				typeof name?.name === 'string' &&
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

type NamedLog = {
	names: Array<string | { name: string }>;
};

function normalize_family_name(name: string) {
	return name.trim().toLowerCase();
}

export function family_names_match(left: string, right: string) {
	const target = normalize_family_name(right);
	return target.length > 0 && normalize_family_name(left) === target;
}

/**
 * Keep only combat candidates that contain the configured family name.
 *
 * The role offsets can move after a BDO patch, so this deliberately checks
 * every extracted name instead of assuming that the family is already at a
 * known index. The editor can then be used to select the correct roles.
 */
export function candidate_involves_family(log: NamedLog, family_name: string) {
	return log.names.some((entry) => {
		const name = typeof entry === 'string' ? entry : entry.name;
		return family_names_match(name, family_name);
	});
}
