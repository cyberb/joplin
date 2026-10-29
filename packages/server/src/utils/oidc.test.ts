import { authorizationUrl, codeChallenge, isAdmin, parseState, serializeState, userFromClaims } from './oidc';
import { OidcConfig } from './types';

const oidc: OidcConfig = {
	enabled: true,
	issuerUrl: 'https://auth.example.com',
	issuerSocket: '',
	clientId: 'joplin',
	clientSecret: 'secret',
	adminGroup: 'syncloud',
	organizationDisplayName: '',
};

describe('oidc', () => {

	test('should round trip the state cookie', () => {
		const state = { state: 'abc', verifier: 'def', relayState: 'app-login' as const };
		expect(parseState(serializeState(state))).toEqual(state);
	});

	test('should reject a malformed state cookie', () => {
		expect(parseState('')).toBeNull();
		expect(parseState(undefined)).toBeNull();
		expect(parseState('abc.def')).toBeNull();
		expect(parseState('abc.def.other-login')).toBeNull();
		expect(parseState('.def.web-login')).toBeNull();
	});

	test('should build a PKCE authorization url', () => {
		const url = new URL(authorizationUrl({
			issuer: 'https://auth.example.com',
			authorization_endpoint: 'https://auth.example.com/api/oidc/authorization',
			token_endpoint: '',
			userinfo_endpoint: '',
		}, oidc, { state: 'abc', verifier: 'def', relayState: 'web-login' }, 'https://joplin.example.com/api/oidc'));

		expect(url.origin + url.pathname).toBe('https://auth.example.com/api/oidc/authorization');
		expect(url.searchParams.get('response_type')).toBe('code');
		expect(url.searchParams.get('client_id')).toBe('joplin');
		expect(url.searchParams.get('redirect_uri')).toBe('https://joplin.example.com/api/oidc');
		expect(url.searchParams.get('scope')).toBe('openid profile email groups');
		expect(url.searchParams.get('state')).toBe('abc');
		expect(url.searchParams.get('code_challenge')).toBe(codeChallenge('def'));
		expect(url.searchParams.get('code_challenge_method')).toBe('S256');
	});

	test('should compute the S256 challenge from RFC 7636', () => {
		expect(codeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
	});

	test('should map userinfo claims', () => {
		expect(userFromClaims({ email: 'a@example.com', name: 'Alice', groups: ['syncloud', 1] })).toEqual({
			email: 'a@example.com',
			displayName: 'Alice',
			groups: ['syncloud'],
		});
		expect(userFromClaims({ email: 'b@example.com', preferred_username: 'bob' }).displayName).toBe('bob');
		expect(userFromClaims({ email: 'c@example.com' }).displayName).toBe('c@example.com');
	});

	test('should grant admin by group only when an admin group is configured', () => {
		expect(isAdmin(oidc, { email: '', displayName: '', groups: ['syncloud'] })).toBe(true);
		expect(isAdmin(oidc, { email: '', displayName: '', groups: [] })).toBe(false);
		expect(isAdmin({ ...oidc, adminGroup: '' }, { email: '', displayName: '', groups: ['syncloud'] })).toBeUndefined();
	});

});
