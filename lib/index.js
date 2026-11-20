import { isLoopbackHost } from "@deepseek-ai/dsh-host-webserver";
// src/index.ts
/** Stable Cordis plugin name. */
const name = "dsh-local-browser-access";
/** Wait for the Host Connection and its authentication registry. */
const inject = ["connection", "connection.authentication"];
/** Read one Host authority from either Web Fetch or node:http headers. */
function requestHost(request) {
	const headers = request.headers;
	if (headers instanceof Headers) return headers.get("host") ?? void 0;
	const host = headers.host;
	return typeof host === "string" ? host : void 0;
}
/** Read one request header from either the Fetch or node:http representation. */
function requestHeader(request, name) {
	const headers = request.headers;
	if (headers instanceof Headers) return headers.get(name) ?? void 0;
	const value = headers[name];
	return typeof value === "string" ? value : void 0;
}
/** Restrict the source-check exception to a bare top-level GET of the app shell. */
function isLoopbackDocumentNavigation(request) {
	return request.method === "GET" && request.url.pathname === "/" && request.url.search === "" && requestHeader(request, "sec-fetch-mode") === "navigate" && requestHeader(request, "sec-fetch-dest") === "document";
}
/** Accept only a bare loopback authority such as localhost:3080 or [::1]:3080. */
function isLoopbackAuthority(authority) {
	if (authority !== authority.trim() || /[\s\\/@?#]/.test(authority)) return false;
	let url;
	try {
		url = new URL(`http://${authority}`);
	} catch {
		return false;
	}
	if (url.username !== "" || url.password !== "" || url.pathname !== "/" || url.search !== "" || url.hash !== "") return false;
	if (url.hostname === "localhost") return true;
	const hostname = url.hostname.startsWith("[") && url.hostname.endsWith("]") ? url.hostname.slice(1, -1) : url.hostname;
	return isLoopbackHost(hostname);
}
/**
* Register a loopback-only fallback Peer when this Host has a local WebServer.
* @param ctx - plugin scope with the Host Connection services.
*/
function apply(ctx) {
	ctx.inject([
		"connection",
		"connection.authentication",
		"webServer"
	], (hostCtx) => {
		const webServer = hostCtx.get("webServer");
		const connection = hostCtx.get("connection");
		const authentication = hostCtx.get("connection.authentication");
		if (webServer === void 0 || connection === void 0 || authentication === void 0) {
			hostCtx.logger.warn("dsh-local-browser-access: disabled because required Host services could not be resolved");
			return;
		}
		const bindHost = webServer.host;
		if (!(typeof bindHost === "string" && isLoopbackHost(bindHost))) {
			hostCtx.logger.warn(`dsh-local-browser-access: disabled because webServer binds non-loopback address ${JSON.stringify(bindHost)}`);
			return;
		}
		const peer = connection.createPeer({ principal: { kind: "owner" } });
		const removeDocumentAdmission = hostCtx.on("webserver/authorize", (request) => {
			const host = requestHost(request);
			if (host !== void 0 && isLoopbackAuthority(host) && isLoopbackDocumentNavigation(request)) return {
				kind: "allow",
				peer
			};
		}, { prepend: true });
		const unregister = authentication.register({ authenticate(request) {
			const host = requestHost(request);
			return host !== void 0 && isLoopbackAuthority(host) ? peer : void 0;
		} });
		hostCtx.effect(() => async () => {
			removeDocumentAdmission();
			await unregister();
			await peer.dispose();
		}, "dsh-local-browser-access: loopback authentication");
		hostCtx.logger.info(`dsh-local-browser-access: enabled for loopback listener ${bindHost}; loopback document navigation only`);
	});
}
export { apply, inject, name };
