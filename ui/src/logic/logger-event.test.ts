import { describe, expect, it } from 'vitest';

import { is_same_candidate, parse_logger_candidate } from './logger-event';

describe('logger event parsing', () => {
	it('parses a structured candidate with a variable name count', () => {
		const event = {
			type: 'candidate',
			identifier: '630100af12',
			time: '12:34:56',
			names: [
				{ name: 'Guild', offset: 12 },
				{ name: 'FamilyOne', offset: 200 },
				{ name: 'FamilyTwo', offset: 420 }
			],
			hex: '630100af12'
		};

		expect(parse_logger_candidate('IKUSA_EVENT ' + JSON.stringify(event))).toEqual({
			identifier: event.identifier,
			time: event.time,
			names: event.names,
			hex: event.hex
		});
	});

	it('keeps compatibility with the legacy comma-separated output', () => {
		const data =
			'630100af12,12:34:56,Guild 12,FamilyOne 200,CharOne 300,FamilyTwo 420,CharTwo 500,630100af12';

		const result = parse_logger_candidate(data);

		expect(result?.names).toHaveLength(5);
		expect(result?.names[1]).toEqual({ name: 'FamilyOne', offset: 200 });
	});

	it('deduplicates equal candidates', () => {
		const candidate = {
			identifier: '630100af12',
			time: '12:34:56',
			names: [
				{ name: 'Guild', offset: 12 },
				{ name: 'FamilyOne', offset: 200 },
				{ name: 'FamilyTwo', offset: 420 }
			],
			hex: '00'
		};

		expect(is_same_candidate(candidate, { ...candidate })).toBe(true);
	});
});
