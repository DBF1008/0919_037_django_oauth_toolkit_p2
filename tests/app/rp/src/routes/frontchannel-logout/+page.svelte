<script lang="ts">
	// OpenID Connect Front-Channel Logout 1.0 RP endpoint.
	// The OpenID Provider loads this page inside a hidden iframe and appends
	// `iss` (and `sid` when session support is required) to the URL.
	import { onMount } from 'svelte';
	import { page } from '$app/stores';

	let issuer = '';
	let sessionId = '';

	onMount(() => {
		issuer = String($page.url.searchParams.get('iss') ?? '');
		sessionId = String($page.url.searchParams.get('sid') ?? '');

		try {
			const storedIssuer = localStorage.getItem('oidc_issuer');
			// Only act when the notification comes from our trusted OP.
			if (issuer && storedIssuer && issuer !== storedIssuer) {
				return;
			}
			if (sessionId) {
				localStorage.removeItem(`oidc_session_${sessionId}`);
			} else {
				localStorage.removeItem('oidc_access_token');
				localStorage.removeItem('oidc_id_token');
			}
		} catch {
			// Storage may be unavailable inside third-party contexts.
		}
	});
</script>

<!--svelte-ignore a11y-no-noninteractive-element-interactions-->
<!-- The RP keeps this page blank; it is only ever rendered inside an OP iframe. -->
<div data-iss={issuer} data-sid={sessionId} hidden></div>
