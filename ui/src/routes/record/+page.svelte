<script lang="ts">
	import { type LoggerCallback, start_logger } from '../../logic/logger-wrapper';
	import { onDestroy, onMount } from 'svelte';
	import Logger from '../../components/create-config/logger.svelte';
	import { get_config, type Config, type LogType } from '../../components/create-config/config';
	import { is_same_candidate, parse_logger_candidate } from '../../logic/logger-event';

	let logs: LogType[] = [];
	let is_destroyed = false;
	let retry_count = 0;
	let config: Config;
	let capture_status = 'Starting Black Desert connection detection...';

	const logger_callback: LoggerCallback = (data, status) => {
		if (status === 'running') {
			if (data.startsWith('Black Desert endpoints:')) {
				capture_status = data.includes('no Black Desert process endpoints found')
					? 'Game process was not detected; scanning all TCP and UDP traffic.'
					: data;
			}
			const new_log = parse_logger_candidate(data);
			if (new_log) {
				if (logs.some((log) => is_same_candidate(log, new_log))) return;
				logs.push(new_log);
				logs = logs;
			} else if (data.includes('Error while reading network.')) {
				alert('Error while reading network. Please notify me on Discord.');
			}
		} else if (status === ('error' as any)) {
			console.error(data);
			alert(
				'An error occured while trying to start the logger. Error message: ' +
					data +
					'\nLogger will be restarted.'
			);
			if (!is_destroyed && retry_count < 3) {
				start_logger(
					logger_callback,
					'analyze',
					(config.all_interfaces ? '-i' : '') + (config.ip_filter ? ' -p' : '')
				);
				retry_count++;
			} else if (!is_destroyed && retry_count >= 3) {
				alert('Tried to start logger 3 times, but failed. Please try again.');
			} else {
				retry_count = 0;
			}
		} else if (status === 'terminated') {
			if (!is_destroyed && retry_count < 3) {
				start_logger(
					logger_callback,
					'analyze',
					(config.all_interfaces ? '-i' : '') + (config.ip_filter ? ' -p' : '')
				);
				retry_count++;
			} else if (!is_destroyed && retry_count >= 3) {
				alert('Tried to start logger 3 times, but failed. Please try again.');
			} else {
				retry_count = 0;
			}
		} else {
			alert('Unknown status: ' + status);
		}
	};

	onMount(async () => {
		config = await get_config();
		start_logger(
			logger_callback,
			'analyze',
			(config.all_interfaces ? '-i' : '') + (config.ip_filter ? ' -p' : '')
		);
	});
	onDestroy(() => {
		is_destroyed = true;
	});
</script>

<Logger {logs} height={375} status_message={capture_status} />
