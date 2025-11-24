<?php

namespace TypechoPlugin\Fail2ban;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Api
{
    public static function isIpBanned(string $ip): bool
    {
        return Guard::isIpBanned($ip);
    }
}
