<?php
declare(strict_types=1);

final class FdSentinel
{
    private array $options = [
        'format' => 'table', 'summary' => false, 'pid' => null, 'name' => null, 'type' => null,
        'min-fds' => 0, 'warn' => 70.0, 'critical' => 90.0,
        'top' => 0, 'interval' => 0.0, 'count' => 1,
        'details' => false, 'deleted-only' => false,
        'inspect-fd' => null, 'inspect-pid' => null, 'explain' => false,
        'system' => false, 'mounts' => false, 'socket-summary' => false,
        'health' => false, 'diagnostics' => false, 'sort' => 'fds',
        'reverse' => false, 'max-details' => 0, 'threshold-delta' => 0,
    ];

    public function run(array $argv): int
    {
        try {
            $this->parse($argv);
            if (!is_dir('/proc/self/fd')) {
                throw new RuntimeException('Linux procfs is required');
            }
            if ($this->options['inspect-pid'] !== null) {
                $inspector = new FdDeepInspector();
                $payload = $inspector->inspect((int) $this->options['inspect-pid'], $this->options['inspect-fd']);
                echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR), PHP_EOL;
                return 0;
            }
            $previous = [];
            for ($iteration = 1; $iteration <= $this->options['count']; $iteration++) {
                $result = $this->scan($previous);
                $previous = [];
                foreach ($result['processes'] as $process) {
                    $previous[$process['pid']] = ['start_time' => $process['start_time'], 'fds' => $process['fds']];
                }
                $this->output($result, $iteration);
                if ($this->options['format'] === 'table') {
                    $extra = new FdExtendedReport();
                    $extra->render($result, $this->options);
                }
                if ($iteration < $this->options['count']) {
                    usleep((int) round($this->options['interval'] * 1000000));
                }
            }
            return 0;
        } catch (Throwable $e) {
            fwrite(STDERR, 'fd-sentinel: ' . $e->getMessage() . PHP_EOL);
            return 1;
        }
    }

    private function parse(array $argv): void
    {
        for ($i = 1; $i < count($argv); $i++) {
            $arg = $argv[$i];
            if (in_array($arg, ['-h', '--help'], true)) {
                $this->help();
                exit(0);
            }
            if (in_array($arg, ['--summary', '--details', '--deleted-only', '--explain', '--system', '--mounts', '--socket-summary', '--health', '--diagnostics', '--reverse'], true)) {
                $this->options[substr($arg, 2)] = true;
                continue;
            }
            if (!str_starts_with($arg, '--')) {
                throw new InvalidArgumentException("Unknown argument: $arg");
            }
            $parts = explode('=', substr($arg, 2), 2);
            $key = $parts[0];
            if (!array_key_exists($key, $this->options)) {
                throw new InvalidArgumentException("Unknown option: --$key");
            }
            $value = $parts[1] ?? null;
            if ($value === null) {
                if (!isset($argv[$i + 1])) {
                    throw new InvalidArgumentException("Missing value for --$key");
                }
                $value = $argv[++$i];
            }
            if (in_array($key, ['pid', 'min-fds', 'top', 'count', 'inspect-fd', 'inspect-pid', 'max-details', 'threshold-delta'], true)) {
                if (!ctype_digit($value)) {
                    throw new InvalidArgumentException("--$key requires a nonnegative integer");
                }
                $value = (int) $value;
            } elseif (in_array($key, ['warn', 'critical', 'interval'], true)) {
                if (!is_numeric($value) || !is_finite((float) $value)) {
                    throw new InvalidArgumentException("--$key requires a finite number");
                }
                $value = (float) $value;
            }
            $this->options[$key] = $value;
        }
        if (!in_array($this->options['format'], ['table', 'json', 'csv'], true)) {
            throw new InvalidArgumentException('Format must be table, json, or csv');
        }
        if ($this->options['count'] < 1 || $this->options['count'] > 100000 || $this->options['interval'] < 0 || $this->options['interval'] > 86400) {
            throw new InvalidArgumentException('Invalid count or interval');
        }
        if ($this->options['warn'] < 0 || $this->options['critical'] > 100 || $this->options['warn'] >= $this->options['critical']) {
            throw new InvalidArgumentException('Thresholds must satisfy 0 <= warn < critical <= 100');
        }
        if ($this->options['pid'] !== null && $this->options['pid'] < 1) {
            throw new InvalidArgumentException('PID must be positive');
        }
        if (!in_array($this->options['sort'], ['fds', 'pid', 'name', 'deleted', 'usage', 'delta', 'uid'], true)) {
            throw new InvalidArgumentException('Invalid sort field');
        }
        if ($this->options['count'] > 1 && $this->options['interval'] <= 0) {
            throw new InvalidArgumentException('Repeated sampling requires --interval greater than zero');
        }
    }

    private function help(): void
    {
        echo <<<'TEXT'
fd-sentinel-php | Linux file descriptor diagnostics

Usage: php main.php [options]
  --format table|json|csv
  --summary               Show process summary only
  --pid N                 Inspect one process
  --name TEXT             Filter by process name substring
  --type TYPE             Filter processes containing descriptor type
  --min-fds N             Minimum open descriptors
  --warn PERCENT          Warning threshold (default 70)
  --critical PERCENT      Critical threshold (default 90)
  --top N                 Show highest N matching processes (0 = all)
  --details               Include individual descriptors
  --deleted-only          Show only processes with deleted open files
  --interval SECONDS      Delay between samples
  --count N               Number of samples (default 1)
  --sort FIELD            fds, pid, name, deleted, usage, delta, uid
  --reverse               Reverse sorting
  --max-details N         Limit descriptor details per process
  --inspect-pid N         Deep inspect one process as JSON
  --inspect-fd N          Limit deep inspection to one descriptor
  --system                Show system file table utilization
  --mounts                Show filesystem descriptor distribution
  --socket-summary        Show socket family and state counts
  --health                Show system health assessment
  --diagnostics           Show /proc access diagnostics
  --explain               Explain observed descriptor risks
  --help                  Show help

TEXT;
        echo PHP_EOL;
    }

    private function scan(array $previous): array
    {
        $processes = [];
        $totals = ['processes' => 0, 'descriptors' => 0, 'deleted' => 0, 'warning' => 0, 'critical' => 0, 'unreadable' => 0];
        $entries = @scandir('/proc');
        if ($entries === false) {
            throw new RuntimeException('Cannot list /proc');
        }
        foreach ($entries as $entry) {
            if (!ctype_digit($entry)) {
                continue;
            }
            $pid = (int) $entry;
            if ($this->options['pid'] !== null && $pid !== $this->options['pid']) {
                continue;
            }
            $process = $this->inspect($pid, $previous[$pid] ?? null);
            if ($process === null) {
                $totals['unreadable']++;
                continue;
            }
            if ($this->options['name'] !== null && stripos($process['name'], $this->options['name']) === false) {
                continue;
            }
            if ($process['fds'] < $this->options['min-fds']) {
                continue;
            }
            if ($this->options['type'] !== null && !isset($process['types'][$this->options['type']])) {
                continue;
            }
            if ($this->options['deleted-only'] && $process['deleted'] === 0) {
                continue;
            }
            $totals['processes']++;
            $totals['descriptors'] += $process['fds'];
            $totals['deleted'] += $process['deleted'];
            if ($process['status'] === 'WARNING') {
                $totals['warning']++;
            } elseif ($process['status'] === 'CRITICAL') {
                $totals['critical']++;
            }
            $processes[] = $process;
        }
        $sort = $this->options['sort'];
        $reverse = $this->options['reverse'];
        usort($processes, static function (array $a, array $b) use ($sort, $reverse): int {
            $key = match ($sort) {
                'usage' => 'usage_percent',
                default => $sort,
            };
            $cmp = ($b[$key] ?? 0) <=> ($a[$key] ?? 0);
            if ($reverse) $cmp = -$cmp;
            return $cmp ?: ($a['pid'] <=> $b['pid']);
        });
        if ($this->options['top'] > 0) {
            $processes = array_slice($processes, 0, $this->options['top']);
        }
        return ['timestamp' => gmdate('c'), 'summary' => $totals, 'processes' => $processes];
    }

    private function inspect(int $pid, ?array $previous): ?array
    {
        $base = "/proc/$pid";
        $fdPath = "$base/fd";
        $entries = @scandir($fdPath);
        if ($entries === false) {
            return null;
        }
        $name = trim((string) @file_get_contents("$base/comm"));
        $statusText = @file_get_contents("$base/status");
        $uid = null;
        $state = null;
        if (is_string($statusText)) {
            if (preg_match('/^Uid:\s*(\d+)/m', $statusText, $match)) {
                $uid = (int) $match[1];
            }
            if (preg_match('/^State:\s*(\S+)/m', $statusText, $match)) {
                $state = $match[1];
            }
        }
        $startTime = $this->startTime($pid);
        $limit = $this->softLimit($pid);
        $types = [];
        $deleted = 0;
        $descriptors = [];
        $fds = 0;
        foreach ($entries as $entry) {
            if (!ctype_digit($entry)) {
                continue;
            }
            $target = @readlink("$fdPath/$entry");
            if ($target === false) {
                continue;
            }
            $fds++;
            $type = $this->classify($target, "$fdPath/$entry");
            $types[$type] = ($types[$type] ?? 0) + 1;
            $isDeleted = str_ends_with($target, ' (deleted)');
            if ($isDeleted) {
                $deleted++;
            }
            if ($this->options['details']) {
                if ($this->options['max-details'] === 0 || count($descriptors) < $this->options['max-details']) {
                    $descriptors[] = ['fd' => (int) $entry, 'type' => $type, 'target' => $target, 'deleted' => $isDeleted];
                }
            }
        }
        if ($this->options['details']) {
            usort($descriptors, static fn(array $a, array $b): int => $a['fd'] <=> $b['fd']);
        }
        ksort($types);
        $usage = $limit !== null && $limit > 0 ? round($fds / $limit * 100, 2) : null;
        $status = $usage === null ? 'UNKNOWN' : ($usage >= $this->options['critical'] ? 'CRITICAL' : ($usage >= $this->options['warn'] ? 'WARNING' : 'OK'));
        $delta = $previous !== null && $previous['start_time'] !== null && $previous['start_time'] === $startTime
            ? $fds - $previous['fds'] : null;
        $result = [
            'pid' => $pid, 'name' => $name, 'uid' => $uid, 'state' => $state,
            'start_time' => $startTime, 'fds' => $fds, 'soft_limit' => $limit,
            'usage_percent' => $usage, 'status' => $status, 'deleted' => $deleted,
            'delta' => $delta, 'types' => $types,
        ];
        if ($this->options['details']) {
            $result['descriptors'] = $descriptors;
        }
        return $result;
    }

    private function classify(string $target, string $fdPath): string
    {
        if (str_starts_with($target, 'socket:[')) return 'socket';
        if (str_starts_with($target, 'pipe:[')) return 'pipe';
        if (str_starts_with($target, 'anon_inode:')) {
            if (preg_match('/^anon_inode:\[?([^\]]+)/', $target, $m)) {
                return 'anon:' . $m[1];
            }
            return 'anon';
        }
        if (str_starts_with($target, 'memfd:') || str_starts_with($target, '/memfd:')) return 'memfd';
        $mode = @filetype($fdPath);
        return match ($mode) {
            'dir' => 'directory', 'file' => 'file', 'link' => 'symlink',
            'fifo' => 'fifo', 'char' => 'character', 'block' => 'block',
            default => 'other',
        };
    }

    private function softLimit(int $pid): ?int
    {
        $text = @file_get_contents("/proc/$pid/limits");
        if (!is_string($text)) return null;
        foreach (explode("\n", $text) as $line) {
            if (preg_match('/^Max open files\s+(\S+)\s+(\S+)/', $line, $m)) {
                return ctype_digit($m[1]) ? (int) $m[1] : null;
            }
        }
        return null;
    }

    private function startTime(int $pid): ?string
    {
        $stat = @file_get_contents("/proc/$pid/stat");
        if (!is_string($stat)) return null;
        $pos = strrpos($stat, ')');
        if ($pos === false) return null;
        $fields = preg_split('/\s+/', trim(substr($stat, $pos + 1)));
        return $fields[19] ?? null;
    }

    private function output(array $result, int $iteration): void
    {
        $format = $this->options['format'];
        if ($format === 'json') {
            echo json_encode(['sample' => $iteration] + $result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR), PHP_EOL;
            return;
        }
        if ($format === 'csv') {
            $out = fopen('php://stdout', 'w');
            if ($out === false) throw new RuntimeException('Cannot open stdout');
            fputcsv($out, ['sample', 'timestamp', 'pid', 'name', 'uid', 'state', 'fds', 'soft_limit', 'usage_percent', 'status', 'deleted', 'delta', 'types']);
            foreach ($result['processes'] as $p) {
                fputcsv($out, [$iteration, $result['timestamp'], $p['pid'], $p['name'], $p['uid'], $p['state'], $p['fds'], $p['soft_limit'], $p['usage_percent'], $p['status'], $p['deleted'], $p['delta'], json_encode($p['types'])]);
            }
            fclose($out);
            return;
        }
        echo "FD SENTINEL | {$result['timestamp']} | Sample $iteration\n";
        if ($this->options['summary']) {
            $s = $result['summary'];
            printf("Processes: %d | FDs: %d | Deleted: %d | Warning: %d | Critical: %d | Unreadable: %d\n", $s['processes'], $s['descriptors'], $s['deleted'], $s['warning'], $s['critical'], $s['unreadable']);
            return;
        }
        echo str_repeat('=', 108), PHP_EOL;
        printf("%-8s %-23s %-7s %-10s %-10s %-9s %-8s %-8s %-8s\n", 'PID', 'PROCESS', 'FDS', 'LIMIT', 'USAGE', 'STATUS', 'DELETED', 'DELTA', 'UID');
        foreach ($result['processes'] as $p) {
            printf("%-8d %-23.23s %-7d %-10s %-10s %-9s %-8d %-8s %-8s\n",
                $p['pid'], $p['name'], $p['fds'], $p['soft_limit'] === null ? '-' : (string) $p['soft_limit'],
                $p['usage_percent'] === null ? '-' : $p['usage_percent'] . '%', $p['status'], $p['deleted'],
                $p['delta'] === null ? '-' : sprintf('%+d', $p['delta']), $p['uid'] === null ? '-' : (string) $p['uid']);
            if ($this->options['details']) {
                foreach ($p['descriptors'] as $fd) {
                    printf("    FD %-6d %-18.18s %s\n", $fd['fd'], $fd['type'], $fd['target']);
                }
            }
        }
        $s = $result['summary'];
        printf("\nMatched processes: %d | FDs: %d | Deleted: %d | Warning: %d | Critical: %d | Unreadable: %d\n\n",
            $s['processes'], $s['descriptors'], $s['deleted'], $s['warning'], $s['critical'], $s['unreadable']);
    }
}



final class FdProcReader
{
    public function text(string $path, int $limit = 1048576): ?string
    {
        if ($limit < 1 || !is_file($path)) {
            return null;
        }
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return null;
        }
        try {
            $data = @stream_get_contents($handle, $limit);
            return is_string($data) ? $data : null;
        } finally {
            fclose($handle);
        }
    }

    public function lines(string $path): array
    {
        $text = $this->text($path);
        if ($text === null) {
            return [];
        }
        return preg_split('/\r?\n/', trim($text)) ?: [];
    }

    public function pairs(string $path): array
    {
        $result = [];
        foreach ($this->lines($path) as $line) {
            $position = strpos($line, ':');
            if ($position === false) {
                continue;
            }
            $key = trim(substr($line, 0, $position));
            $value = trim(substr($line, $position + 1));
            if ($key !== '') {
                $result[$key] = $value;
            }
        }
        return $result;
    }

    public function numericDirectories(string $path): array
    {
        $entries = @scandir($path);
        if (!is_array($entries)) {
            return [];
        }
        $numbers = [];
        foreach ($entries as $entry) {
            if (ctype_digit($entry)) {
                $numbers[] = (int) $entry;
            }
        }
        sort($numbers, SORT_NUMERIC);
        return $numbers;
    }

    public function links(string $path): array
    {
        $result = [];
        foreach ($this->numericDirectories($path) as $fd) {
            $target = @readlink($path . '/' . $fd);
            if (is_string($target)) {
                $result[$fd] = $target;
            }
        }
        return $result;
    }

    public function integer(string $path): ?int
    {
        $text = $this->text($path, 128);
        if ($text === null) {
            return null;
        }
        $text = trim($text);
        if (!ctype_digit($text)) {
            return null;
        }
        return (int) $text;
    }

    public function commandLine(int $pid): array
    {
        $text = $this->text("/proc/$pid/cmdline");
        if ($text === null) {
            return [];
        }
        return array_values(array_filter(
            explode("\0", $text),
            static fn(string $part): bool => $part !== ''
        ));
    }

    public function environmentKeys(int $pid): array
    {
        $text = $this->text("/proc/$pid/environ");
        if ($text === null) {
            return [];
        }
        $keys = [];
        foreach (explode("\0", $text) as $entry) {
            $position = strpos($entry, '=');
            if ($position !== false) {
                $keys[] = substr($entry, 0, $position);
            }
        }
        sort($keys);
        return $keys;
    }

    public function status(int $pid): array
    {
        return $this->pairs("/proc/$pid/status");
    }

    public function limits(int $pid): array
    {
        $result = [];
        foreach ($this->lines("/proc/$pid/limits") as $line) {
            if (preg_match('/^(.*?)\s{2,}(\S+)\s+(\S+)\s+(\S+)$/', $line, $matches)) {
                $result[trim($matches[1])] = [
                    'soft' => $matches[2],
                    'hard' => $matches[3],
                    'units' => $matches[4],
                ];
            }
        }
        return $result;
    }

    public function fdinfo(int $pid, int $fd): array
    {
        return $this->pairs("/proc/$pid/fdinfo/$fd");
    }

    public function namespaceLinks(int $pid): array
    {
        $names = [
            'cgroup',
            'ipc',
            'mnt',
            'net',
            'pid',
            'pid_for_children',
            'time',
            'user',
            'uts',
        ];
        $result = [];
        foreach ($names as $name) {
            $link = @readlink("/proc/$pid/ns/$name");
            if (is_string($link)) {
                $result[$name] = $link;
            }
        }
        return $result;
    }

    public function stat(int $pid): array
    {
        $text = $this->text("/proc/$pid/stat");
        if ($text === null) {
            return [];
        }
        $open = strpos($text, '(');
        $close = strrpos($text, ')');
        if ($open === false || $close === false || $close <= $open) {
            return [];
        }
        $fields = preg_split('/\s+/', trim(substr($text, $close + 1)));
        if (!is_array($fields) || count($fields) < 22) {
            return [];
        }
        return [
            'pid' => $pid,
            'comm' => substr($text, $open + 1, $close - $open - 1),
            'state' => $fields[0],
            'ppid' => (int) $fields[1],
            'pgrp' => (int) $fields[2],
            'session' => (int) $fields[3],
            'tty_nr' => (int) $fields[4],
            'minflt' => (int) $fields[7],
            'majflt' => (int) $fields[9],
            'utime' => (int) $fields[11],
            'stime' => (int) $fields[12],
            'threads' => (int) $fields[17],
            'starttime' => $fields[19],
            'vsize' => (int) $fields[20],
            'rss_pages' => (int) $fields[21],
        ];
    }

    public function fileDescriptorCount(int $pid): ?int
    {
        $entries = @scandir("/proc/$pid/fd");
        if (!is_array($entries)) {
            return null;
        }
        $count = 0;
        foreach ($entries as $entry) {
            if (ctype_digit($entry)) {
                $count++;
            }
        }
        return $count;
    }

    public function processExists(int $pid): bool
    {
        return $pid > 0 && is_dir("/proc/$pid");
    }

    public function procMounts(): array
    {
        $mounts = [];
        foreach ($this->lines('/proc/self/mountinfo') as $line) {
            $separator = strpos($line, ' - ');
            if ($separator === false) {
                continue;
            }
            $left = preg_split('/\s+/', substr($line, 0, $separator));
            $right = preg_split('/\s+/', substr($line, $separator + 3));
            if (!is_array($left) || !is_array($right)) {
                continue;
            }
            if (count($left) < 6 || count($right) < 3) {
                continue;
            }
            $mounts[] = [
                'id' => (int) $left[0],
                'parent' => (int) $left[1],
                'device' => $left[2],
                'root' => $left[3],
                'mount' => $left[4],
                'options' => $left[5],
                'filesystem' => $right[0],
                'source' => $right[1],
                'super_options' => $right[2],
            ];
        }
        return $mounts;
    }

    public function fileTable(): array
    {
        $text = $this->text('/proc/sys/fs/file-nr', 256);
        if ($text === null) {
            return [];
        }
        $parts = preg_split('/\s+/', trim($text));
        if (!is_array($parts) || count($parts) < 3) {
            return [];
        }
        $allocated = (int) $parts[0];
        $unused = (int) $parts[1];
        $maximum = (int) $parts[2];
        return [
            'allocated' => $allocated,
            'unused' => $unused,
            'maximum' => $maximum,
            'utilization_percent' => $maximum > 0
                ? round(100 * $allocated / $maximum, 2)
                : null,
        ];
    }

    public function kernelLimits(): array
    {
        return [
            'file_max' => $this->integer('/proc/sys/fs/file-max'),
            'nr_open' => $this->integer('/proc/sys/fs/nr_open'),
            'aio_max_nr' => $this->integer('/proc/sys/fs/aio-max-nr'),
            'aio_nr' => $this->integer('/proc/sys/fs/aio-nr'),
            'inotify_max_user_instances' => $this->integer('/proc/sys/fs/inotify/max_user_instances'),
            'inotify_max_user_watches' => $this->integer('/proc/sys/fs/inotify/max_user_watches'),
            'inotify_max_queued_events' => $this->integer('/proc/sys/fs/inotify/max_queued_events'),
            'epoll_max_user_watches' => $this->integer('/proc/sys/fs/epoll/max_user_watches'),
        ];
    }
}

final class FdTargetClassifier
{
    public function classify(string $target): string
    {
        if (preg_match('/^socket:\[\d+\]$/', $target)) {
            return 'socket';
        }
        if (preg_match('/^pipe:\[\d+\]$/', $target)) {
            return 'pipe';
        }
        if (str_starts_with($target, 'anon_inode:')) {
            return $this->anonymousKind($target);
        }
        if (str_starts_with($target, 'memfd:')) {
            return 'memfd';
        }
        if (str_starts_with($target, '/memfd:')) {
            return 'memfd';
        }
        if (str_starts_with($target, '/')) {
            return 'filesystem';
        }
        if (str_starts_with($target, 'net:[')) {
            return 'network_namespace';
        }
        return 'unknown';
    }

    public function anonymousKind(string $target): string
    {
        if (preg_match('/^anon_inode:\[([^\]]+)\]/', $target, $match)) {
            return 'anon:' . $match[1];
        }
        if (preg_match('/^anon_inode:([^\s]+)/', $target, $match)) {
            return 'anon:' . $match[1];
        }
        return 'anon';
    }

    public function inode(string $target): ?int
    {
        if (preg_match('/^(?:socket|pipe):\[(\d+)\]$/', $target, $match)) {
            return (int) $match[1];
        }
        return null;
    }

    public function isDeleted(string $target): bool
    {
        return str_ends_with($target, ' (deleted)');
    }

    public function isAbstractSocket(string $target): bool
    {
        return str_starts_with($target, '@');
    }

    public function isLikelyKernelObject(string $target): bool
    {
        return str_starts_with($target, 'anon_inode:')
            || str_starts_with($target, 'socket:[')
            || str_starts_with($target, 'pipe:[');
    }

    public function filesystemPath(string $target): ?string
    {
        if (!str_starts_with($target, '/')) {
            return null;
        }
        if ($this->isDeleted($target)) {
            return substr($target, 0, -strlen(' (deleted)'));
        }
        return $target;
    }

    public function pathExtension(string $target): ?string
    {
        $path = $this->filesystemPath($target);
        if ($path === null) {
            return null;
        }
        $extension = pathinfo($path, PATHINFO_EXTENSION);
        return $extension === '' ? null : strtolower($extension);
    }

    public function filesystemRegion(string $target): string
    {
        $path = $this->filesystemPath($target);
        if ($path === null) {
            return 'non-filesystem';
        }
        foreach (['/proc/', '/sys/', '/dev/', '/run/', '/tmp/', '/var/', '/home/', '/usr/', '/opt/'] as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return rtrim($prefix, '/');
            }
        }
        return '/other';
    }

    public function fdFlags(array $info): array
    {
        $raw = $info['flags'] ?? null;
        if (!is_string($raw) || !preg_match('/^[0-7]+$/', $raw)) {
            return [];
        }
        $flags = octdec($raw);
        $access = $flags & 3;
        return [
            'raw_octal' => $raw,
            'readable' => $access === 0 || $access === 2,
            'writable' => $access === 1 || $access === 2,
            'append' => ($flags & 02000) !== 0,
            'nonblocking' => ($flags & 04000) !== 0,
            'sync' => ($flags & 04010000) !== 0,
            'cloexec' => ($flags & 02000000) !== 0,
        ];
    }

    public function descriptorPosition(array $info): ?int
    {
        $position = $info['pos'] ?? null;
        return is_string($position) && ctype_digit($position)
            ? (int) $position
            : null;
    }

    public function mountId(array $info): ?int
    {
        $value = $info['mnt_id'] ?? null;
        return is_string($value) && ctype_digit($value)
            ? (int) $value
            : null;
    }

    public function inotifyWatches(array $lines): int
    {
        $count = 0;
        foreach ($lines as $line) {
            if (str_starts_with($line, 'inotify ')) {
                $count++;
            }
        }
        return $count;
    }

    public function describe(string $type): string
    {
        return match ($type) {
            'socket' => 'Communication endpoint managed by the kernel',
            'pipe' => 'Unidirectional kernel-managed byte stream',
            'memfd' => 'Anonymous memory-backed file descriptor',
            'filesystem' => 'Path-backed file or directory',
            'anon:eventfd' => 'Kernel event notification counter',
            'anon:eventpoll' => 'Kernel epoll interest set',
            'anon:inotify' => 'Filesystem event notification descriptor',
            'anon:timerfd' => 'Kernel timer descriptor',
            'anon:signalfd' => 'Signal delivery descriptor',
            'anon:pidfd' => 'Stable process reference descriptor',
            'anon:userfaultfd' => 'Userspace page fault notification descriptor',
            'anon:io_uring' => 'Asynchronous I/O submission and completion ring',
            default => 'Descriptor target reported by procfs',
        };
    }
}

final class FdDeepInspector
{
    private FdProcReader $reader;
    private FdTargetClassifier $classifier;

    public function __construct()
    {
        $this->reader = new FdProcReader();
        $this->classifier = new FdTargetClassifier();
    }

    public function inspect(int $pid, ?int $selectedFd = null): array
    {
        if (!$this->reader->processExists($pid)) {
            throw new RuntimeException("Process $pid does not exist");
        }
        $before = $this->reader->stat($pid);
        $status = $this->reader->status($pid);
        $limits = $this->reader->limits($pid);
        $links = $this->reader->links("/proc/$pid/fd");
        $descriptors = [];
        foreach ($links as $fd => $target) {
            if ($selectedFd !== null && $selectedFd !== $fd) {
                continue;
            }
            $descriptors[] = $this->inspectDescriptor($pid, $fd, $target);
        }
        $after = $this->reader->stat($pid);
        $reused = isset($before['starttime'], $after['starttime'])
            && $before['starttime'] !== $after['starttime'];
        if ($reused) {
            throw new RuntimeException('PID changed identity during inspection');
        }
        return [
            'timestamp' => gmdate('c'),
            'pid' => $pid,
            'process' => [
                'name' => trim((string) $this->reader->text("/proc/$pid/comm", 4096)),
                'cmdline' => $this->reader->commandLine($pid),
                'status' => $status,
                'stat' => $after,
                'limits' => $limits,
                'namespaces' => $this->reader->namespaceLinks($pid),
                'cwd' => @readlink("/proc/$pid/cwd") ?: null,
                'root' => @readlink("/proc/$pid/root") ?: null,
                'exe' => @readlink("/proc/$pid/exe") ?: null,
            ],
            'descriptor_count' => count($links),
            'selected_descriptor' => $selectedFd,
            'descriptors' => $descriptors,
            'analysis' => $this->analyze($descriptors, $limits),
        ];
    }

    private function inspectDescriptor(int $pid, int $fd, string $target): array
    {
        $info = $this->reader->fdinfo($pid, $fd);
        $type = $this->classifier->classify($target);
        $path = $this->classifier->filesystemPath($target);
        $metadata = $this->filesystemMetadata($path);
        return [
            'fd' => $fd,
            'target' => $target,
            'type' => $type,
            'description' => $this->classifier->describe($type),
            'deleted' => $this->classifier->isDeleted($target),
            'inode' => $this->classifier->inode($target),
            'filesystem_region' => $this->classifier->filesystemRegion($target),
            'extension' => $this->classifier->pathExtension($target),
            'position' => $this->classifier->descriptorPosition($info),
            'mount_id' => $this->classifier->mountId($info),
            'flags' => $this->classifier->fdFlags($info),
            'fdinfo' => $info,
            'filesystem' => $metadata,
        ];
    }

    private function filesystemMetadata(?string $path): array
    {
        if ($path === null) {
            return [];
        }
        $stat = @stat($path);
        if (!is_array($stat)) {
            return [
                'available' => false,
            ];
        }
        return [
            'available' => true,
            'device' => $stat['dev'] ?? null,
            'inode' => $stat['ino'] ?? null,
            'mode' => $stat['mode'] ?? null,
            'links' => $stat['nlink'] ?? null,
            'uid' => $stat['uid'] ?? null,
            'gid' => $stat['gid'] ?? null,
            'size' => $stat['size'] ?? null,
            'blocks' => $stat['blocks'] ?? null,
            'accessed' => $stat['atime'] ?? null,
            'modified' => $stat['mtime'] ?? null,
            'changed' => $stat['ctime'] ?? null,
        ];
    }

    private function analyze(array $descriptors, array $limits): array
    {
        $types = [];
        $regions = [];
        $deleted = [];
        $nonblocking = 0;
        $writable = 0;
        $cloexec = 0;
        foreach ($descriptors as $descriptor) {
            $type = $descriptor['type'];
            $region = $descriptor['filesystem_region'];
            $types[$type] = ($types[$type] ?? 0) + 1;
            $regions[$region] = ($regions[$region] ?? 0) + 1;
            if ($descriptor['deleted']) {
                $deleted[] = $descriptor['fd'];
            }
            if ($descriptor['flags']['nonblocking'] ?? false) {
                $nonblocking++;
            }
            if ($descriptor['flags']['writable'] ?? false) {
                $writable++;
            }
            if ($descriptor['flags']['cloexec'] ?? false) {
                $cloexec++;
            }
        }
        arsort($types);
        arsort($regions);
        return [
            'types' => $types,
            'regions' => $regions,
            'deleted_fds' => $deleted,
            'nonblocking' => $nonblocking,
            'writable' => $writable,
            'cloexec' => $cloexec,
            'open_files_limit' => $limits['Max open files'] ?? null,
        ];
    }
}

final class FdExtendedReport
{
    private FdProcReader $reader;
    private FdTargetClassifier $classifier;

    public function __construct()
    {
        $this->reader = new FdProcReader();
        $this->classifier = new FdTargetClassifier();
    }

    public function render(array $result, array $options): void
    {
        if ($options['system']) {
            $this->systemReport();
        }
        if ($options['mounts']) {
            $this->mountReport($result);
        }
        if ($options['socket-summary']) {
            $this->socketReport($result);
        }
        if ($options['health']) {
            $this->healthReport($result, $options);
        }
        if ($options['diagnostics']) {
            $this->diagnosticReport();
        }
        if ($options['explain']) {
            $this->explainReport($result, $options);
        }
    }

    private function heading(string $title): void
    {
        echo PHP_EOL;
        echo $title, PHP_EOL;
        echo str_repeat('-', strlen($title)), PHP_EOL;
    }

    private function value(mixed $value): string
    {
        if ($value === null) {
            return '-';
        }
        if (is_bool($value)) {
            return $value ? 'yes' : 'no';
        }
        if (is_float($value)) {
            return sprintf('%.2f', $value);
        }
        if (is_array($value)) {
            return implode(', ', array_map('strval', $value));
        }
        return (string) $value;
    }

    private function row(string $label, mixed $value): void
    {
        printf("%-34s %s\n", $label, $this->value($value));
    }

    private function systemReport(): void
    {
        $this->heading('System file descriptor table');
        $table = $this->reader->fileTable();
        if ($table === []) {
            echo "File table information unavailable\n";
        } else {
            foreach ($table as $key => $value) {
                $this->row($key, $value);
            }
        }
        $this->heading('Kernel file descriptor limits');
        foreach ($this->reader->kernelLimits() as $key => $value) {
            $this->row($key, $value);
        }
        $this->heading('Current process namespace');
        foreach ($this->reader->namespaceLinks(getmypid()) as $key => $value) {
            $this->row($key, $value);
        }
    }

    private function mountReport(array $result): void
    {
        $this->heading('Mount and filesystem descriptor distribution');
        $mounts = $this->reader->procMounts();
        $mountById = [];
        foreach ($mounts as $mount) {
            $mountById[$mount['id']] = $mount;
        }
        $counts = [];
        $unavailable = 0;
        foreach ($result['processes'] as $process) {
            $pid = $process['pid'];
            foreach ($this->reader->numericDirectories("/proc/$pid/fdinfo") as $fd) {
                $info = $this->reader->fdinfo($pid, $fd);
                $id = $this->classifier->mountId($info);
                if ($id === null) {
                    $unavailable++;
                    continue;
                }
                $key = (string) $id;
                $counts[$key] = ($counts[$key] ?? 0) + 1;
            }
        }
        arsort($counts);
        printf("%-10s %-9s %-14s %s\n", 'MOUNT ID', 'FD COUNT', 'FILESYSTEM', 'MOUNT POINT');
        foreach ($counts as $id => $count) {
            $mount = $mountById[(int) $id] ?? null;
            printf(
                "%-10s %-9d %-14.14s %s\n",
                $id,
                $count,
                $mount['filesystem'] ?? '-',
                $mount['mount'] ?? 'not visible in current mount namespace'
            );
        }
        $this->row('Missing mount IDs', $unavailable);
        $this->row('Mount entries in current namespace', count($mounts));
    }

    private function socketReport(array $result): void
    {
        $this->heading('Socket descriptor summary');
        $socketInodes = [];
        $pipeInodes = [];
        $socketReferences = 0;
        $pipeReferences = 0;
        $byProcess = [];
        foreach ($result['processes'] as $process) {
            $pid = $process['pid'];
            $links = $this->reader->links("/proc/$pid/fd");
            $count = 0;
            foreach ($links as $target) {
                if (str_starts_with($target, 'socket:[')) {
                    $inode = $this->classifier->inode($target);
                    if ($inode !== null) {
                        $socketInodes[$inode] = true;
                    }
                    $socketReferences++;
                    $count++;
                }
                if (str_starts_with($target, 'pipe:[')) {
                    $inode = $this->classifier->inode($target);
                    if ($inode !== null) {
                        $pipeInodes[$inode] = true;
                    }
                    $pipeReferences++;
                }
            }
            if ($count > 0) {
                $byProcess[$pid] = [
                    'name' => $process['name'],
                    'count' => $count,
                ];
            }
        }
        $this->row('Socket FD references', $socketReferences);
        $this->row('Distinct socket inodes', count($socketInodes));
        $this->row('Pipe FD references', $pipeReferences);
        $this->row('Distinct pipe inodes', count($pipeInodes));
        $socketIndex = new FdSocketIndex();
        foreach ($socketIndex->summary() as $family => $data) {
            $this->row($family . ' visible sockets', $data['count']);
            $this->row($family . ' listening sockets', $data['listening']);
        }
        uasort($byProcess, static fn(array $a, array $b): int => $b['count'] <=> $a['count']);
        echo PHP_EOL;
        printf("%-9s %-9s %s\n", 'PID', 'SOCKETS', 'PROCESS');
        foreach (array_slice($byProcess, 0, 20, true) as $pid => $item) {
            printf("%-9d %-9d %s\n", $pid, $item['count'], $item['name']);
        }
    }

    private function healthReport(array $result, array $options): void
    {
        $this->heading('Descriptor health assessment');
        $total = count($result['processes']);
        $statuses = [
            'OK' => 0,
            'WARNING' => 0,
            'CRITICAL' => 0,
            'UNKNOWN' => 0,
        ];
        $deleted = 0;
        $positive = 0;
        $negative = 0;
        $stable = 0;
        $unknownDelta = 0;
        $highUsage = [];
        $deletedProcesses = [];
        foreach ($result['processes'] as $process) {
            $status = $process['status'];
            $statuses[$status] = ($statuses[$status] ?? 0) + 1;
            $deleted += $process['deleted'];
            if ($process['deleted'] > 0) {
                $deletedProcesses[] = $process;
            }
            if ($process['delta'] === null) {
                $unknownDelta++;
            } elseif ($process['delta'] > 0) {
                $positive++;
            } elseif ($process['delta'] < 0) {
                $negative++;
            } else {
                $stable++;
            }
            if ($process['usage_percent'] !== null &&
                $process['usage_percent'] >= $options['warn']) {
                $highUsage[] = $process;
            }
        }
        $this->row('Processes evaluated', $total);
        foreach ($statuses as $status => $count) {
            $this->row('Processes ' . strtolower($status), $count);
        }
        $this->row('Open deleted descriptors', $deleted);
        $this->row('Processes with growing FD counts', $positive);
        $this->row('Processes with shrinking FD counts', $negative);
        $this->row('Processes with stable FD counts', $stable);
        $this->row('Processes without delta baseline', $unknownDelta);
        $this->heading('Processes above warning threshold');
        if ($highUsage === []) {
            echo "None in the selected sample\n";
        }
        foreach ($highUsage as $process) {
            printf(
                "PID %-8d %-24.24s %7.2f%% %s\n",
                $process['pid'],
                $process['name'],
                $process['usage_percent'],
                $process['status']
            );
        }
        $this->heading('Processes with deleted open files');
        if ($deletedProcesses === []) {
            echo "None in the selected sample\n";
        }
        foreach ($deletedProcesses as $process) {
            printf(
                "PID %-8d %-24.24s deleted=%d\n",
                $process['pid'],
                $process['name'],
                $process['deleted']
            );
        }
    }

    private function diagnosticReport(): void
    {
        $this->heading('Procfs diagnostic checks');
        $checks = [
            '/proc' => is_dir('/proc'),
            '/proc/self' => is_dir('/proc/self'),
            '/proc/self/fd' => is_dir('/proc/self/fd'),
            '/proc/self/fdinfo' => is_dir('/proc/self/fdinfo'),
            '/proc/self/status' => is_readable('/proc/self/status'),
            '/proc/self/limits' => is_readable('/proc/self/limits'),
            '/proc/self/stat' => is_readable('/proc/self/stat'),
            '/proc/self/mountinfo' => is_readable('/proc/self/mountinfo'),
            '/proc/sys/fs/file-nr' => is_readable('/proc/sys/fs/file-nr'),
            '/proc/sys/fs/file-max' => is_readable('/proc/sys/fs/file-max'),
            '/proc/net/unix' => is_readable('/proc/net/unix'),
            '/proc/net/tcp' => is_readable('/proc/net/tcp'),
            '/proc/net/udp' => is_readable('/proc/net/udp'),
        ];
        foreach ($checks as $path => $available) {
            printf("%-40s %s\n", $path, $available ? 'available' : 'unavailable');
        }
        $this->heading('Runtime');
        $this->row('PHP version', PHP_VERSION);
        $this->row('PHP SAPI', PHP_SAPI);
        $this->row('Operating system', PHP_OS_FAMILY);
        $this->row('Architecture', php_uname('m'));
        $this->row('Kernel release', php_uname('r'));
        $this->row('Effective user', function_exists('posix_geteuid') ? posix_geteuid() : 'unknown');
        $this->row('Current PID', getmypid());
        $this->row('Memory usage', memory_get_usage(true));
        $this->row('Memory peak', memory_get_peak_usage(true));
        $this->row('Procfs processes visible', count($this->reader->numericDirectories('/proc')));
    }

    private function explainReport(array $result, array $options): void
    {
        $this->heading('Interpretation');
        $critical = [];
        $warning = [];
        $deleted = [];
        $growth = [];
        foreach ($result['processes'] as $process) {
            if ($process['status'] === 'CRITICAL') {
                $critical[] = $process;
            } elseif ($process['status'] === 'WARNING') {
                $warning[] = $process;
            }
            if ($process['deleted'] > 0) {
                $deleted[] = $process;
            }
            if ($process['delta'] !== null &&
                $process['delta'] >= max(1, $options['threshold-delta'])) {
                $growth[] = $process;
            }
        }
        if ($critical === [] && $warning === [] && $deleted === [] && $growth === []) {
            echo "No configured warning conditions were observed in this sample.\n";
        }
        if ($critical !== []) {
            echo "Some processes are at or above the critical descriptor threshold.\n";
            echo "Investigate workload, descriptor lifetime, and process limits.\n";
        }
        if ($warning !== []) {
            echo "Some processes are approaching their configured descriptor limits.\n";
            echo "Compare repeated samples before concluding that a leak exists.\n";
        }
        if ($deleted !== []) {
            echo "Deleted files remain referenced by open descriptors.\n";
            echo "Disk space may remain allocated until the last reference is closed.\n";
            echo "Inspect file size and process ownership before taking action.\n";
        }
        if ($growth !== []) {
            echo "Some descriptor counts increased between available samples.\n";
            echo "Growth alone does not establish a resource leak.\n";
            echo "Check whether the increase stabilizes under normal load.\n";
        }
        echo "Observations reflect only processes visible through the current procfs view.\n";
        echo "A process may exit or change its descriptors during the scan.\n";
        echo "Descriptor count and kernel file-table allocation are different metrics.\n";
    }
}

final class FdSocketIndex
{
    private FdProcReader $reader;

    public function __construct()
    {
        $this->reader = new FdProcReader();
    }

    public function inspect(): array
    {
        return [
            'unix' => $this->unixSockets(),
            'tcp4' => $this->internetSockets('/proc/net/tcp', 'tcp', 4),
            'tcp6' => $this->internetSockets('/proc/net/tcp6', 'tcp', 6),
            'udp4' => $this->internetSockets('/proc/net/udp', 'udp', 4),
            'udp6' => $this->internetSockets('/proc/net/udp6', 'udp', 6),
        ];
    }

    public function index(): array
    {
        $index = [];
        foreach ($this->inspect() as $family => $sockets) {
            foreach ($sockets as $socket) {
                if (!isset($socket['inode'])) {
                    continue;
                }
                $index[(string) $socket['inode']] = [
                    'family' => $family,
                    'socket' => $socket,
                ];
            }
        }
        return $index;
    }

    public function summary(): array
    {
        $result = [];
        foreach ($this->inspect() as $family => $sockets) {
            $states = [];
            $owners = [];
            $listening = 0;
            foreach ($sockets as $socket) {
                $state = $socket['state'] ?? 'unknown';
                $states[$state] = ($states[$state] ?? 0) + 1;
                $uid = $socket['uid'] ?? null;
                if ($uid !== null) {
                    $owners[$uid] = ($owners[$uid] ?? 0) + 1;
                }
                if (($socket['listening'] ?? false) === true) {
                    $listening++;
                }
            }
            arsort($states);
            arsort($owners);
            $result[$family] = [
                'count' => count($sockets),
                'listening' => $listening,
                'states' => $states,
                'uids' => $owners,
            ];
        }
        return $result;
    }

    public function unixSockets(): array
    {
        $result = [];
        $lines = $this->reader->lines('/proc/net/unix');
        foreach (array_slice($lines, 1) as $line) {
            $parts = preg_split('/\s+/', trim($line), 8);
            if (!is_array($parts) || count($parts) < 7) {
                continue;
            }
            if (!ctype_digit($parts[6])) {
                continue;
            }
            $flags = hexdec($parts[3]);
            $type = hexdec($parts[4]);
            $state = hexdec($parts[5]);
            $result[] = [
                'inode' => (int) $parts[6],
                'reference_count' => hexdec($parts[1]),
                'protocol' => hexdec($parts[2]),
                'flags' => $flags,
                'type' => $this->unixType($type),
                'state' => $this->unixState($state),
                'listening' => ($flags & 0x10000) !== 0,
                'path' => $parts[7] ?? '',
            ];
        }
        return $result;
    }

    public function internetSockets(string $path, string $protocol, int $version): array
    {
        $result = [];
        $lines = $this->reader->lines($path);
        foreach (array_slice($lines, 1) as $line) {
            $parts = preg_split('/\s+/', trim($line));
            if (!is_array($parts) || count($parts) < 10) {
                continue;
            }
            if (!ctype_digit($parts[9])) {
                continue;
            }
            $state = strtoupper($parts[3]);
            $local = $this->parseEndpoint($parts[1], $version);
            $remote = $this->parseEndpoint($parts[2], $version);
            $result[] = [
                'inode' => (int) $parts[9],
                'protocol' => $protocol,
                'ip_version' => $version,
                'local' => $local,
                'remote' => $remote,
                'state' => $this->tcpState($state),
                'uid' => ctype_digit($parts[7]) ? (int) $parts[7] : null,
                'listening' => $protocol === 'tcp' && $state === '0A',
            ];
        }
        return $result;
    }

    private function parseEndpoint(string $value, int $version): array
    {
        $parts = explode(':', $value, 2);
        if (count($parts) !== 2) {
            return ['raw' => $value];
        }
        $address = $parts[0];
        $port = hexdec($parts[1]);
        if ($version === 4 && strlen($address) === 8) {
            $bytes = hex2bin($address);
            if ($bytes !== false) {
                $ip = inet_ntop(strrev($bytes));
                if ($ip !== false) {
                    return [
                        'address' => $ip,
                        'port' => $port,
                    ];
                }
            }
        }
        if ($version === 6 && strlen($address) === 32) {
            $bytes = hex2bin($address);
            if ($bytes !== false) {
                $reordered = '';
                for ($i = 0; $i < 16; $i += 4) {
                    $reordered .= strrev(substr($bytes, $i, 4));
                }
                $ip = inet_ntop($reordered);
                if ($ip !== false) {
                    return [
                        'address' => $ip,
                        'port' => $port,
                    ];
                }
            }
        }
        return [
            'raw' => $address,
            'port' => $port,
        ];
    }

    private function unixType(int $value): string
    {
        return match ($value) {
            1 => 'stream',
            2 => 'datagram',
            5 => 'seqpacket',
            default => 'other:' . $value,
        };
    }

    private function unixState(int $value): string
    {
        return match ($value) {
            0 => 'free',
            1 => 'unconnected',
            2 => 'connecting',
            3 => 'connected',
            4 => 'disconnecting',
            default => 'unknown:' . $value,
        };
    }

    private function tcpState(string $value): string
    {
        return match ($value) {
            '01' => 'established',
            '02' => 'syn_sent',
            '03' => 'syn_recv',
            '04' => 'fin_wait1',
            '05' => 'fin_wait2',
            '06' => 'time_wait',
            '07' => 'close',
            '08' => 'close_wait',
            '09' => 'last_ack',
            '0A' => 'listen',
            '0B' => 'closing',
            '0C' => 'new_syn_recv',
            default => 'unknown:' . $value,
        };
    }

    public function describeInode(int $inode): ?array
    {
        if ($inode <= 0) {
            return null;
        }
        $index = $this->index();
        return $index[(string) $inode] ?? null;
    }

    public function countByState(string $family): array
    {
        $all = $this->inspect();
        $sockets = $all[$family] ?? [];
        $counts = [];
        foreach ($sockets as $socket) {
            $state = $socket['state'] ?? 'unknown';
            $counts[$state] = ($counts[$state] ?? 0) + 1;
        }
        arsort($counts);
        return $counts;
    }

    public function countByPort(string $family): array
    {
        $all = $this->inspect();
        $sockets = $all[$family] ?? [];
        $counts = [];
        foreach ($sockets as $socket) {
            $port = $socket['local']['port'] ?? null;
            if ($port === null) {
                continue;
            }
            $counts[$port] = ($counts[$port] ?? 0) + 1;
        }
        arsort($counts);
        return $counts;
    }

    public function listeningSockets(): array
    {
        $result = [];
        foreach ($this->inspect() as $family => $sockets) {
            foreach ($sockets as $socket) {
                if (($socket['listening'] ?? false) !== true) {
                    continue;
                }
                $result[] = [
                    'family' => $family,
                    'inode' => $socket['inode'],
                    'local' => $socket['local'] ?? null,
                    'path' => $socket['path'] ?? null,
                ];
            }
        }
        return $result;
    }
}

exit((new FdSentinel())->run($argv));
