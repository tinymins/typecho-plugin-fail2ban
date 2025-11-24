<?php

namespace TypechoPlugin\Fail2ban;

use Exception;
use Utils\Helper;
use Typecho\Db;
use Typecho\Request;
use Typecho\Response;
use Typecho\Widget;
use Widget\User;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Guard
{
    private Db $db;
    private Request $request;
    private Response $response;
    private \Typecho\Config $options;
    private User $user;

    public function __construct()
    {
        $this->db = Db::get();
        $this->request = Request::getInstance();
        $this->response = Response::getInstance();
        $this->options = Widget::widget('Widget_Options')->plugin('Fail2ban');
        $this->user = Widget::widget('Widget_User');
    }

    public static function handle($archive): void
    {
        try {
            $guard = new self();
            $guard->process();
        } catch (Exception $e) {
            // keep request alive even when guard fails
        }
    }

    private function process(): void
    {
        if (!$this->isEnabled()) {
            return;
        }

        if ($this->isTrustedUser()) {
            return;
        }

        $ip = $this->request->getIp();
        if (empty($ip) || $this->isWhitelisted($ip)) {
            return;
        }

        $now = $this->now();

        if ($this->isBanned($ip, $now)) {
            $this->deny();
            return;
        }

        $path = $this->request->getRequestUri();
        if ($path === null) {
            return;
        }

        $rules = $this->parseRules();
        if (empty($rules)) {
            return;
        }

        foreach ($rules as $rule) {
            if ($this->matches($path, $rule)) {
                $this->registerMatch($ip, $path, $rule, $now);
            }
        }
    }

    private function isEnabled(): bool
    {
        return isset($this->options->enabled) ? $this->options->enabled !== '0' : true;
    }

    private function isTrustedUser(): bool
    {
        if (!$this->user->hasLogin()) {
            return false;
        }
        return $this->user->pass('administrator', true);
    }

    private function isWhitelisted(string $ip): bool
    {
        $lines = isset($this->options->whitelist) ? $this->options->whitelist : '';
        if ($lines === '') {
            return false;
        }
        foreach ($this->splitLines($lines) as $mask) {
            if ($mask === '') {
                continue;
            }
            if ($this->ipMatches($ip, $mask)) {
                return true;
            }
        }
        return false;
    }

    private function splitLines(string $value): array
    {
        $parts = preg_split('/\r\n|\r|\n/', $value);
        return $parts ? array_map('trim', $parts) : [];
    }

    private function ipMatches(string $ip, string $needle): bool
    {
        if (false === strpos($needle, '/')) {
            return $ip === $needle;
        }

        [$subnet, $prefix] = explode('/', $needle, 2);
        $prefix = (int) $prefix;
        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false) {
            return false;
        }
        $maxPrefix = strlen($subnetBin) * 8;
        if ($prefix < 0 || $prefix > $maxPrefix) {
            return false;
        }
        $bytes = intdiv($prefix, 8);
        $bits = $prefix % 8;
        if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
            return false;
        }
        if ($bits === 0) {
            return true;
        }
        $mask = chr(((0xFF << (8 - $bits)) & 0xFF));
        return (ord($ipBin[$bytes]) & ord($mask)) === (ord($subnetBin[$bytes]) & ord($mask));
    }

    private function now(): int
    {
        $options = Helper::options();
        return (int) ($options->gmtTime + ($options->timezone - $options->serverTimezone));
    }

    private function isBanned(string $ip, int $now): bool
    {
        try {
            $ban = $this->db->fetchRow(
                $this->db->select()
                    ->from('table.fail2ban_bans')
                    ->where('ip = ?', $ip)
                    ->where('active = ?', 1)
                    ->order('expires_at', Db::SORT_DESC)
                    ->limit(1)
            );
        } catch (Exception $e) {
            return false;
        }

        if (empty($ban)) {
            return false;
        }

        if ((int) $ban['expires_at'] <= $now) {
            try {
                $this->db->query(
                    $this->db->update('table.fail2ban_bans')
                        ->rows(['active' => 0])
                        ->where('id = ?', $ban['id'])
                );
            } catch (Exception $e) {
            }
            return false;
        }

        return true;
    }

    private function parseRules(): array
    {
        $rules = [];
        $raw = isset($this->options->rules) && trim($this->options->rules) !== ''
            ? $this->options->rules
            : Plugin::getDefaultRules();

        $fallbackWindow = max(1, (int) $this->options->windowMinutes);
        $fallbackThreshold = max(1, (int) $this->options->thresholdHits);
        $fallbackBan = max(1, (int) $this->options->banMinutes);

        foreach ($this->splitLines($raw) as $line) {
            if ($line === '' || strpos($line, '#') === 0) {
                continue;
            }
            $segments = array_map('trim', explode('|', $line));
            if (count($segments) < 4) {
                continue;
            }
            $banMinutes = trim(array_pop($segments));
            $thresholdHits = trim(array_pop($segments));
            $windowMinutes = trim(array_pop($segments));
            $pattern = trim(implode('|', $segments));
            if ($pattern === '') {
                continue;
            }

            $window = is_numeric($windowMinutes) ? max(1, (int) $windowMinutes) : $fallbackWindow;
            $threshold = is_numeric($thresholdHits) ? max(1, (int) $thresholdHits) : $fallbackThreshold;
            $ban = is_numeric($banMinutes) ? max(1, (int) $banMinutes) : $fallbackBan;

            $isRegex = stripos($pattern, 'regex:') === 0;
            $regex = $isRegex ? $this->compileRegex(substr($pattern, 6)) : $this->compileWildcard($pattern);
            if ($regex === null) {
                continue;
            }

            $rules[] = [
                'pattern' => $pattern,
                'regex' => $regex,
                'window' => $window,
                'threshold' => $threshold,
                'ban' => $ban,
                'hash' => md5($pattern . '|' . $window . '|' . $threshold . '|' . $ban)
            ];
        }

        return $rules;
    }

    private function compileRegex(?string $pattern = null): ?string
    {
        if ($pattern === null) {
            return null;
        }
        $pattern = trim($pattern);
        if ($pattern === '') {
            return null;
        }
        $delim = substr($pattern, 0, 1);
        $end = strrpos($pattern, $delim);
        if ($end !== false && $end !== 0) {
            return $pattern;
        }
        return '/' . str_replace('/', '\/', $pattern) . '/i';
    }

    private function compileWildcard(string $pattern): ?string
    {
        $escaped = preg_quote($pattern, '/');
        return '/^' . str_replace(['\\*', '\\?'], ['.*', '.'], $escaped) . '$/i';
    }

    private function matches(string $path, array $rule): bool
    {
        return (bool) @preg_match($rule['regex'], $path);
    }

    private function registerMatch(string $ip, string $path, array $rule, int $now): void
    {
        $window = $rule['window'] * 60;
        try {
            $record = $this->db->fetchRow(
                $this->db->select()
                    ->from('table.fail2ban_hits')
                    ->where('ip = ?', $ip)
                    ->where('rule_hash = ?', $rule['hash'])
                    ->limit(1)
            );
        } catch (Exception $e) {
            return;
        }

        $counter = 1;
        $firstSeen = $now;
        if (!empty($record)) {
            $firstSeen = (int) $record['first_seen'];
            if ($now - $firstSeen > $window) {
                $counter = 1;
                $firstSeen = $now;
            } else {
                $counter = (int) $record['counter'] + 1;
            }

            try {
                $this->db->query(
                    $this->db->update('table.fail2ban_hits')
                        ->rows([
                            'last_path' => $path,
                            'last_seen' => $now,
                            'first_seen' => $firstSeen,
                            'counter' => $counter
                        ])
                        ->where('id = ?', $record['id'])
                );
            } catch (Exception $e) {
            }
        } else {
            try {
                $this->db->query(
                    $this->db->insert('table.fail2ban_hits')->rows([
                        'ip' => $ip,
                        'rule_pattern' => $rule['pattern'],
                        'rule_hash' => $rule['hash'],
                        'last_path' => $path,
                        'first_seen' => $firstSeen,
                        'last_seen' => $now,
                        'counter' => $counter
                    ])
                );
            } catch (Exception $e) {
                return;
            }
        }

        if ($counter >= $rule['threshold']) {
            $this->banIp($ip, $path, $rule, $counter, $firstSeen, $now);
            try {
                $this->db->query(
                    $this->db->delete('table.fail2ban_hits')
                        ->where('ip = ?', $ip)
                        ->where('rule_hash = ?', $rule['hash'])
                );
            } catch (Exception $e) {
            }
        }
    }

    private function banIp(string $ip, string $path, array $rule, int $hits, int $firstSeen, int $now): void
    {
        $expiresAt = $now + $rule['ban'] * 60;
        $reason = sprintf('Blocked by rule %s after %d hits in %d minutes', $rule['pattern'], $hits, $rule['window']);

        try {
            $existing = $this->db->fetchRow(
                $this->db->select()
                    ->from('table.fail2ban_bans')
                    ->where('ip = ?', $ip)
                    ->where('active = ?', 1)
                    ->limit(1)
            );
        } catch (Exception $e) {
            $existing = null;
        }

        if (!empty($existing)) {
            $update = [
                'rule_pattern' => $rule['pattern'],
                'rule_hash' => $rule['hash'],
                'reason' => $reason,
                'hits' => $hits,
                'threshold' => $rule['threshold'],
                'window_size' => $rule['window'],
                'ban_length' => $rule['ban'],
                'last_detected' => $now,
                'expires_at' => $expiresAt
            ];
            try {
                $this->db->query(
                    $this->db->update('table.fail2ban_bans')
                        ->rows($update)
                        ->where('id = ?', $existing['id'])
                );
            } catch (Exception $e) {
            }
        } else {
            $insert = [
                'ip' => $ip,
                'rule_pattern' => $rule['pattern'],
                'rule_hash' => $rule['hash'],
                'reason' => $reason,
                'hits' => $hits,
                'threshold' => $rule['threshold'],
                'window_size' => $rule['window'],
                'ban_length' => $rule['ban'],
                'first_detected' => $firstSeen,
                'last_detected' => $now,
                'expires_at' => $expiresAt,
                'active' => 1
            ];
            try {
                $this->db->query(
                    $this->db->insert('table.fail2ban_bans')->rows($insert)
                );
            } catch (Exception $e) {
            }
        }

        $this->writeLog($ip, $path, $rule, $hits, $now, $reason);
        $this->deny();
    }

    private function writeLog(string $ip, string $path, array $rule, int $hits, int $now, string $message): void
    {
        try {
            $this->db->query(
                $this->db->insert('table.fail2ban_logs')->rows([
                    'ip' => $ip,
                    'path' => $path,
                    'rule_pattern' => $rule['pattern'],
                    'rule_hash' => $rule['hash'],
                    'hits' => $hits,
                    'created_at' => $now,
                    'message' => $message
                ])
            );
        } catch (Exception $e) {
        }
    }

    private function deny(): void
    {
        $message = isset($this->options->denyMessage) && $this->options->denyMessage !== ''
            ? $this->options->denyMessage
            : 'Access denied.';
        $this->response->setStatus(403);
        $this->response->setContentType('text/html; charset=UTF-8');
        echo $message;
        exit;
    }

    public static function isIpBanned(string $ip): bool
    {
        if ($ip === '') {
            return false;
        }

        static $cache = [];
        if (array_key_exists($ip, $cache)) {
            return $cache[$ip];
        }

        try {
            $db = Db::get();
            $options = Helper::options();
            $now = (int) ($options->gmtTime + ($options->timezone - $options->serverTimezone));

            $row = $db->fetchRow(
                $db->select()
                    ->from('table.fail2ban_bans')
                    ->where('ip = ?', $ip)
                    ->where('active = ?', 1)
                    ->where('expires_at > ?', $now)
                    ->limit(1)
            );

            return $cache[$ip] = !empty($row);
        } catch (Exception $e) {
            return $cache[$ip] = false;
        }
    }
}
