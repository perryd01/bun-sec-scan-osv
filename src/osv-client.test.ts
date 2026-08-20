import {expect, test} from 'bun:test';
import {queryOSV} from './osv-client.ts';

function jsonResponse(body: unknown, ok = true, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {'content-type': 'application/json'},
	});
}

test('sends a batch query with npm ecosystem for each package', async () => {
	const captured: {req?: Request} = {};
	const fetchFn = async (input: Request | string, init?: RequestInit) => {
		captured.req = input instanceof Request ? input : new Request(input, init);
		return jsonResponse({results: []});
	};

	await queryOSV(
		[
			{name: 'event-stream', version: '3.3.6'},
			{name: 'lodash', version: '4.17.21'},
		],
		fetchFn,
	);

	expect(captured.req?.url).toBe('https://api.osv.dev/v1/querybatch');
	expect(captured.req?.method).toBe('POST');
	const body = (await captured.req?.json()) as {
		queries: Array<{version: string; package: {name: string; ecosystem: string}}>;
	};
	expect(body.queries).toEqual([
		{version: '3.3.6', package: {name: 'event-stream', ecosystem: 'npm'}},
		{version: '4.17.21', package: {name: 'lodash', ecosystem: 'npm'}},
	]);
});

test('parses batch results and associates vulns with each package', async () => {
	const fetchFn = async () =>
		jsonResponse({
			results: [
				{vulns: [{id: 'GHSA-1', summary: 'first'}]},
				{vulns: []},
				{vulns: [{id: 'GHSA-2', summary: 'second'}]},
			],
		});

	const results = await queryOSV(
		[
			{name: 'a', version: '1'},
			{name: 'b', version: '1'},
			{name: 'c', version: '1'},
		],
		fetchFn,
	);

	expect(results).toHaveLength(3);
	expect(results[0]?.package.name).toBe('a');
	expect(results[0]?.vulns[0]?.id).toBe('GHSA-1');
	expect(results[1]?.vulns).toEqual([]);
	expect(results[2]?.vulns[0]?.id).toBe('GHSA-2');
});

test('throws when the API returns a non-OK status', async () => {
	const fetchFn = async () => jsonResponse({message: 'boom'}, false, 500);

	expect(async () => queryOSV([{name: 'a', version: '1'}], fetchFn)).toThrow();
});

test('throws when the response is malformed', async () => {
	const fetchFn = async () => jsonResponse({unexpected: true});

	expect(async () => queryOSV([{name: 'a', version: '1'}], fetchFn)).toThrow();
});
