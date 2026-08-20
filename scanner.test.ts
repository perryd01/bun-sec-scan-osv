import {expect, test} from 'bun:test';
import {createScanner} from './src/index.ts';
import type {QueryResult} from './src/osv-client.ts';

function fakeQuery(results: QueryResult[]) {
	return async () => results;
}

test('Scanner should produce a fatal advisory for a vulnerable package', async () => {
	const scanner = createScanner({
		query: fakeQuery([
			{
				package: {name: 'event-stream', version: '3.3.6'},
				vulns: [
					{
						id: 'GHSA-vp9c-fpxx-744v',
						summary: 'Malicious code in event-stream',
						severity: [{type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}],
						references: [{type: 'WEB', url: 'https://example.com/event-stream'}],
					},
				],
			},
		]),
	});

	const advisories = await scanner.scan({packages: []});

	expect(advisories).toEqual([
		{
			level: 'fatal',
			package: 'event-stream',
			url: 'https://example.com/event-stream',
			description: 'Malicious code in event-stream',
		},
	]);
});

test('There should be no advisories if the OSV query returns no vulns', async () => {
	const scanner = createScanner({query: fakeQuery([])});

	const advisories = await scanner.scan({packages: []});
	expect(advisories).toEqual([]);
});

test('Safe packages should return no advisories', async () => {
	const scanner = createScanner({
		query: fakeQuery([
			{
				package: {name: 'lodash', version: '4.17.21'},
				vulns: [],
			},
		]),
	});

	const advisories = await scanner.scan({packages: []});
	expect(advisories).toEqual([]);
});

test('Should handle multiple packages with mixed security status', async () => {
	const scanner = createScanner({
		query: fakeQuery([
			{
				package: {name: 'event-stream', version: '3.3.6'},
				vulns: [
					{
						id: 'GHSA-1',
						summary: 'Malicious',
						severity: [{type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}],
					},
				],
			},
			{
				package: {name: 'lodash', version: '4.17.21'},
				vulns: [],
			},
		]),
	});

	const advisories = await scanner.scan({packages: []});
	expect(advisories).toHaveLength(1);
	expect(advisories[0]?.package).toBe('event-stream');
});

test('Should propagate an error when the OSV query fails', async () => {
	const scanner = createScanner({
		query: async () => {
			throw new Error('OSV query failed');
		},
	});

	expect(async () => scanner.scan({packages: []})).toThrow('OSV query failed');
});
