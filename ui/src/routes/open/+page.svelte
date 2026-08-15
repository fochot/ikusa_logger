<script lang="ts">
	import Button from '../../svelte-ui/elements/button.svelte';
	import { start_logger, type LoggerCallback } from '../../logic/logger-wrapper';
	import Logger from '../../components/create-config/logger.svelte';
	import { open_file } from '../../logic/file';
	import { get_config, type Log, type LogType } from '../../components/create-config/config';
	import { filesystem } from '@neutralinojs/lib';
	import LogEditor from '../../components/create-config/log-editor.svelte';
	import { is_same_candidate, parse_logger_candidate } from '../../logic/logger-event';
	let logs: LogType[] = [];
	let combat_logs: Log[] = [];
	let loading = false;
	let capture_status = 'Choose a PCAP or log file.';

	let is_network = false;

	const log_regex =
		/\[(.+?)\]\s+(\S+)\s+(died to|has killed)\s+(\S+)\s+from\s+(\S+)(?: \(([^,]*),([^)]*)\))?/;

	const logger_callback: LoggerCallback = (data, status) => {
		if (status === 'running') {
			if (data.startsWith('Capture mode:') || data.startsWith('Black Desert endpoints:')) {
				capture_status = data;
			}
			const new_log = parse_logger_candidate(data);
			if (new_log) {
				if (logs.some((log) => is_same_candidate(log, new_log))) return;
				logs.push(new_log);
				logs = logs;
			}
		} else if (status === ('error' as any)) {
			console.error(data);
			loading = false;
		} else if (status === 'terminated') {
			loading = false;
		}
	};

	async function open_pcap() {
		logs = [];
		combat_logs = [];
		const filePaths = await open_file();
		if (filePaths.length === 0) return;
		const config = await get_config();
		const selected_file = filePaths[0];
		const lower_case_file = selected_file.toLowerCase();
		if (lower_case_file.endsWith('.txt') || lower_case_file.endsWith('.log')) {
			const filePath = selected_file;
			is_network = false;
			let data = await filesystem.readFile(filePath);
			if (!data) return;
			logs = [];
			const lines = data.split('\n');
			for (const line of lines) {
				const match = line.match(log_regex);
				if (match) {
					const new_combat_log: Log = {
						time: match[1],
						names: [match[2], match[4], match[5], match[6], match[7]].filter(
							(name): name is string => Boolean(name)
						),
						kill: match[3] === 'has killed'
					};
					combat_logs.push(new_combat_log);
				}
			}
			combat_logs = combat_logs;
		} else {
			is_network = true;
			capture_status = 'Analyzing the original BDO TCP combat stream...';
			start_logger(
				logger_callback,
				'analyze',
				'-f ' + '"' + selected_file + '"' + (config.ip_filter ? ' -p' : '')
			);
			loading = true;
		}
	}
</script>

<Button size="sm" class="mb-2 shrink-0" on:click={open_pcap}>Open File</Button>
{#if is_network}
	<Logger {logs} height={375} {loading} status_message={capture_status} />
{:else}
	<LogEditor logs={combat_logs} height={375} {loading} />
{/if}
