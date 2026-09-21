<script lang="ts">
	// Demonstration RP iframe for OpenID Connect Session Management 1.0,
	// Section 3.1. The parent RP page supplies `op_origin`, `op_iframe` (the
	// OP check_session_iframe URL), `client_id` and `session_state` query
	// parameters and polls the OP iframe with postMessage.
	import { onDestroy, onMount } from 'svelte';
	import { page } from '$app/stores';

	let status = 'pending';
	let timer: ReturnType<typeof setInterval> | undefined;

	function receiveMessage(event: MessageEvent) {
		const opOrigin = String($page.url.searchParams.get('op_origin') ?? '');
		// Only accept messages originating from the OpenID Provider.
		if (event.origin !== opOrigin) {
			return;
		}
		status = String(event.data);
		if (status === 'changed' || status === 'error') {
			if (timer) {
				clearInterval(timer);
			}
			// On "changed" the RP would re-authenticate with prompt=none;
			// on "error" it must not, to avoid infinite request loops.
			if (status === 'changed') {
				window.parent.postMessage('session_changed', window.location.origin);
			}
		}
	}

	function checkSession() {
		const opFrameId = String($page.url.searchParams.get('op_frame_id') ?? 'op');
		const clientId = String($page.url.searchParams.get('client_id') ?? '');
		const sessionState = String($page.url.searchParams.get('session_state') ?? '');
		const opOrigin = String($page.url.searchParams.get('op_origin') ?? '');
		const frame = window.parent.frames.namedItem(opFrameId);
		if (frame) {
			frame.postMessage(`${clientId} ${sessionState}`, opOrigin);
		}
	}

	onMount(() => {
		window.addEventListener('message', receiveMessage);
		checkSession();
		timer = setInterval(checkSession, 5000);
	});

	onDestroy(() => {
		window.removeEventListener('message', receiveMessage);
		if (timer) {
			clearInterval(timer);
		}
	});
</script>

<div data-session-status={status} hidden></div>
