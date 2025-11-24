<?php

namespace TypechoPlugin\Fail2ban;

use Exception;
use Utils\Helper;
use Typecho\Db;
use Typecho\Widget;
use Typecho\Exception as TypechoException;
use Widget\ActionInterface;
use Widget\Security;
use Widget\User;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Action extends Widget implements ActionInterface
{
    private Db $db;

    public function __construct($request, $response, $params = null)
    {
        parent::__construct($request, $response, $params);
        $this->db = Db::get();
    }

    public function action(): void
    {
        Security::alloc()->protect();
        $this->assertAdmin();

        $do = strtolower((string) $this->request->get('do'));
        switch ($do) {
            case 'unban':
                $this->unban();
                break;
            case 'flush':
                $this->flushExpired();
                break;
        }

        $this->response->redirect($this->consoleUrl());
    }

    private function assertAdmin(): void
    {
        $user = User::alloc();
        if (!$user->hasLogin() || !$user->pass('administrator', true)) {
            throw new TypechoException('Access denied', 403);
        }
    }

    private function unban(): void
    {
        $banId = (int) $this->request->get('banId');
        if ($banId <= 0) {
            return;
        }

        $now = $this->now();
        try {
            $this->db->query(
                $this->db->update('table.fail2ban_bans')
                    ->rows([
                        'active' => 0,
                        'expires_at' => $now
                    ])
                    ->where('id = ?', $banId)
            );
        } catch (Exception $e) {
        }
    }

    private function flushExpired(): void
    {
        $now = $this->now();
        try {
            $this->db->query(
                $this->db->update('table.fail2ban_bans')
                    ->rows(['active' => 0])
                    ->where('active = ?', 1)
                    ->where('expires_at <= ?', $now)
            );
        } catch (Exception $e) {
        }
    }

    private function now(): int
    {
        $options = Helper::options();
        return (int) ($options->gmtTime + ($options->timezone - $options->serverTimezone));
    }

    private function consoleUrl(): string
    {
        return Security::alloc()->getAdminUrl('extending.php?panel=' . Plugin::$panel);
    }
}
