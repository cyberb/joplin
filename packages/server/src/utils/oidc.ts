import * as http from 'http';
import * as https from 'https';
import { createHash, randomBytes } from 'crypto';
import config from '../config';
import { cookieDelete, cookieGet, cookieSet } from './cookies';
import { ErrorForbidden } from './errors';
import { redirect } from './routeUtils';
import { AppContext, OidcConfig, OidcRelayState } from './types';

export interface OidcDiscovery {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	userinfo_endpoint: string;
}

export interface OidcUser {
	email: string;
	displayName: string;
	groups: string[];
}

export interface OidcState {
	state: string;
	verifier: string;
	relayState: OidcRelayState;
}

interface OidcHttpResponse {
	status: number;
	body: string;
}

const stateCookieName = 'oidcState';
const relayStates: OidcRelayState[] = ['web-login', 'app-login'];

let discovery_: OidcDiscovery = null;
let useSocket_ = true;

const randomToken = () => randomBytes(32).toString('base64url');

export const codeChallenge = (verifier: string) => createHash('sha256').update(verifier).digest('base64url');

export const redirectUri = () => `${config().apiBaseUrl}/api/oidc`;

export const serializeState = (state: OidcState) => [state.state, state.verifier, state.relayState].join('.');

export const parseState = (value: string): OidcState | null => {
	if (!value) return null;
	const parts = value.split('.');
	if (parts.length !== 3) return null;
	const [state, verifier, relayState] = parts;
	if (!state || !verifier) return null;
	if (!relayStates.includes(relayState as OidcRelayState)) return null;
	return { state, verifier, relayState: relayState as OidcRelayState };
};

export const authorizationUrl = (discovery: OidcDiscovery, oidc: OidcConfig, state: OidcState, callbackUrl: string) => {
	const url = new URL(discovery.authorization_endpoint);
	url.searchParams.set('response_type', 'code');
	url.searchParams.set('client_id', oidc.clientId);
	url.searchParams.set('redirect_uri', callbackUrl);
	url.searchParams.set('scope', 'openid profile email groups');
	url.searchParams.set('state', state.state);
	url.searchParams.set('code_challenge', codeChallenge(state.verifier));
	url.searchParams.set('code_challenge_method', 'S256');
	return url.toString();
};

export const userFromClaims = (claims: Record<string, unknown>): OidcUser => {
	const email = typeof claims.email === 'string' ? claims.email : '';
	const names = [claims.name, claims.preferred_username, email];
	const displayName = names.find(n => typeof n === 'string' && n) as string || '';
	const groups = Array.isArray(claims.groups) ? claims.groups.filter(g => typeof g === 'string') : [];
	return { email, displayName, groups };
};

export const isAdmin = (oidc: OidcConfig, user: OidcUser): boolean | undefined => {
	if (!oidc.adminGroup) return undefined;
	return user.groups.includes(oidc.adminGroup);
};

const checkIfOidcIsEnabled = () => {
	if (!config().oidc.enabled) throw new ErrorForbidden('OpenID Connect not enabled');
};

const send = (url: string, method: string, headers: Record<string, string>, body: string, viaSocket: boolean): Promise<OidcHttpResponse> => {
	const target = new URL(url);
	const options: https.RequestOptions = {
		method,
		path: `${target.pathname}${target.search}`,
		headers: { ...headers, 'Content-Length': `${Buffer.byteLength(body)}` },
		timeout: 30000,
	};

	if (viaSocket) {
		options.socketPath = config().oidc.issuerSocket;
		options.headers = {
			...options.headers,
			'Host': target.host,
			'X-Forwarded-Host': target.host,
			'X-Forwarded-Proto': target.protocol.replace(':', ''),
		};
	} else {
		options.hostname = target.hostname;
		options.port = target.port;
	}

	const transport = viaSocket || target.protocol === 'http:' ? http : https;

	return new Promise((resolve, reject) => {
		const request = transport.request(options, response => {
			let data = '';
			response.setEncoding('utf8');
			response.on('data', (chunk: string) => { data += chunk; });
			response.on('end', () => resolve({ status: response.statusCode, body: data }));
		});
		request.on('timeout', () => request.destroy(new Error(`OIDC request to ${url} timed out`)));
		request.on('error', reject);
		request.end(body);
	});
};

const isIssuerUrl = (url: string) => new URL(url).host === new URL(config().oidc.issuerUrl).host;

const fetchJson = async (url: string, method: string, headers: Record<string, string>, body = '') => {
	const viaSocket = useSocket_ && !!config().oidc.issuerSocket && isIssuerUrl(url);
	const response = await send(url, method, { Accept: 'application/json', ...headers }, body, viaSocket);
	if (response.status !== 200) throw new Error(`OIDC request to ${url} failed: ${response.status} ${response.body}`);
	return JSON.parse(response.body);
};

const loadDiscovery = async (): Promise<OidcDiscovery> => {
	const issuer = config().oidc.issuerUrl;
	const discovery: OidcDiscovery = await fetchJson(`${issuer}/.well-known/openid-configuration`, 'GET', {});
	if (discovery.issuer.replace(/\/+$/, '') !== issuer) {
		throw new Error(`OIDC issuer mismatch: expected ${issuer}, got ${discovery.issuer}`);
	}
	return discovery;
};

export const getDiscovery = async (): Promise<OidcDiscovery> => {
	checkIfOidcIsEnabled();
	if (discovery_) return discovery_;

	try {
		discovery_ = await loadDiscovery();
	} catch (error) {
		if (!useSocket_ || !config().oidc.issuerSocket) throw error;
		useSocket_ = false;
		discovery_ = await loadDiscovery();
	}

	return discovery_;
};

export const startLogin = async (ctx: AppContext, relayState: OidcRelayState) => {
	const discovery = await getDiscovery();
	const state: OidcState = { state: randomToken(), verifier: randomToken(), relayState };
	cookieSet(ctx, stateCookieName, serializeState(state));
	return redirect(ctx, authorizationUrl(discovery, config().oidc, state, redirectUri()));
};

export const finishLogin = async (ctx: AppContext): Promise<{ user: OidcUser; relayState: OidcRelayState }> => {
	const discovery = await getDiscovery();
	const saved = parseState(cookieGet(ctx, stateCookieName));
	cookieDelete(ctx, stateCookieName);

	const query = ctx.query as Record<string, string>;
	if (query.error) throw new ErrorForbidden(`OIDC login failed: ${query.error} ${query.error_description || ''}`);
	if (!saved || query.state !== saved.state) throw new ErrorForbidden('OIDC state mismatch');
	if (query.iss && query.iss !== discovery.issuer) throw new ErrorForbidden('OIDC issuer mismatch');
	if (!query.code) throw new ErrorForbidden('OIDC code missing');

	const oidc = config().oidc;
	const credentials = Buffer.from(`${encodeURIComponent(oidc.clientId)}:${encodeURIComponent(oidc.clientSecret)}`).toString('base64');
	const token = await fetchJson(discovery.token_endpoint, 'POST', {
		'Authorization': `Basic ${credentials}`,
		'Content-Type': 'application/x-www-form-urlencoded',
	}, new URLSearchParams({
		grant_type: 'authorization_code',
		code: query.code,
		redirect_uri: redirectUri(),
		code_verifier: saved.verifier,
	}).toString());

	if (typeof token.access_token !== 'string') throw new ErrorForbidden('OIDC token response has no access token');

	const claims = await fetchJson(discovery.userinfo_endpoint, 'GET', { Authorization: `Bearer ${token.access_token}` });

	return { user: userFromClaims(claims), relayState: saved.relayState };
};
