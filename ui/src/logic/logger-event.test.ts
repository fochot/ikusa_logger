import { describe, expect, it } from 'vitest';

import { candidate_name_at_index, is_same_candidate, parse_logger_candidate } from './logger-event';

describe('logger event parsing', () => {
	it('parses a structured candidate with exactly five validated names', () => {
		const event = {
			type: 'candidate',
			identifier: '630100af12',
			time: '12:34:56',
			names: [
				{ name: 'Guild', offset: 12 },
				{ name: 'FamilyOne', offset: 200 },
				{ name: 'CharOne', offset: 300 },
				{ name: 'FamilyTwo', offset: 420 },
				{ name: 'CharTwo', offset: 500 }
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

	it('rejects candidates with an unexpected field count', () => {
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

		expect(parse_logger_candidate('IKUSA_EVENT ' + JSON.stringify(event))).toBeNull();
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

	it('uses the validated guild field instead of decoding bytes after its terminator', () => {
		const candidate = {
			identifier: '720100fe1a',
			time: '12:34:56',
			names: [
				{ name: 'Conquest', offset: 10 },
				{ name: 'FamilyOne', offset: 404 },
				{ name: 'CharOne', offset: 460 },
				{ name: 'FamilyTwo', offset: 528 },
				{ name: 'CharTwo', offset: 570 }
			],
			hex: '720100fe1a43006f006e00710075006500730074000000ff817c00'
		};

		expect(candidate_name_at_index(candidate, 0)).toBe('Conquest');
		expect(candidate_name_at_index(candidate, 5)).toBe('');
	});

	it('rejects structured events containing a corrupted name', () => {
		const event = {
			type: 'candidate',
			identifier: '720100fe1a',
			time: '12:34:56',
			names: [
				{ name: '\u0001�|Conquest', offset: 10 },
				{ name: 'FamilyOne', offset: 404 },
				{ name: 'CharOne', offset: 460 },
				{ name: 'FamilyTwo', offset: 528 },
				{ name: 'CharTwo', offset: 570 }
			],
			hex: '720100fe1a'
		};

		expect(parse_logger_candidate('IKUSA_EVENT ' + JSON.stringify(event))).toBeNull();
	});
});
