import {expect, test} from 'bun:test';
import {vulnToAdvisory} from './map.ts';

test('maps a high severity vulnerability to a fatal advisory', () => {
	const advisory = vulnToAdvisory('event-stream', {
		id: 'GHSA-...',
		summary: 'Malicious code in event-stream',
		severity: [{type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'}],
		references: [{type: 'WEB', url: 'https://example.com/advisory'}],
	});

	expect(advisory).toEqual({
		level: 'fatal',
		package: 'event-stream',
		url: 'https://example.com/advisory',
		description: 'Malicious code in event-stream',
	});
});

test('maps a low severity vulnerability to a warning advisory', () => {
	const advisory = vulnToAdvisory('lodash', {
		id: 'CVE-...',
		summary: 'Prototype pollution',
		severity: [{type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'}],
		references: [{type: 'WEB', url: 'https://example.com/cve'}],
	});

	expect(advisory.level).toBe('warn');
});

test('maps a vulnerability without a severity score to a warning advisory', () => {
	const advisory = vulnToAdvisory('lodash', {
		id: 'GHSA-...',
		summary: 'Prototype pollution',
	});

	expect(advisory.level).toBe('warn');
});

test('uses null url when there are no references', () => {
	const advisory = vulnToAdvisory('lodash', {
		id: 'GHSA-...',
		summary: 'Something',
	});

	expect(advisory.url).toBeNull();
});

test('falls back to details when summary is absent', () => {
	const advisory = vulnToAdvisory('lodash', {
		id: 'GHSA-...',
		details: 'Longer details text',
	});

	expect(advisory.description).toBe('Longer details text');
});

test('takes the maximum severity score across entries', () => {
	const advisory = vulnToAdvisory('lodash', {
		id: 'CVE-...',
		summary: 'Mixed severity',
		severity: [
			{type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'},
			{type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'},
		],
	});

	expect(advisory.level).toBe('fatal');
});
