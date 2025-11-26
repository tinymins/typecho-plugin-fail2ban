<?php

namespace TypechoPlugin\Fail2ban;

use Typecho\Db;
use Typecho\Plugin\Exception as PluginException;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Migration
{
    private static bool $schemaChecked = false;

    public static function install(): void
    {
        $db = Db::get();
        $adapter = $db->getAdapterName();
        $prefix = $db->getPrefix();

        if (!self::tableExists($db, 'fail2ban_hits')) {
            $scripts = self::schemaScript($adapter);
            if ($scripts === null) {
                throw new PluginException(_t('Fail2ban 暂不支持当前数据库适配器: %s', $adapter));
            }
            $scripts = str_replace('typecho_', $prefix, $scripts);
            self::runSqlScripts($db, $scripts);
        }

        self::upgrade($db);
    }

    public static function upgrade(?Db $db = null): void
    {
        if (self::$schemaChecked) {
            return;
        }

        $db = $db ?: Db::get();
        $adapter = $db->getAdapterName();
        $prefix = $db->getPrefix();

        self::upgrade_1_0_0_to_1_1_0($db, $adapter, $prefix);
        self::upgrade_1_1_0_to_1_2_0($db, $adapter, $prefix);
        self::upgrade_1_2_0_to_1_3_0($db, $adapter, $prefix);

        self::$schemaChecked = true;
    }

    private static function upgrade_1_0_0_to_1_1_0(Db $db, string $adapter, string $prefix): void
    {
        $table = $prefix . 'fail2ban_logs';

        if (self::columnExists($db, $adapter, $table, 'user_agent')) {
            return;
        }

        $sql = null;
        if (stripos($adapter, 'Mysql') !== false) {
            $sql = sprintf('ALTER TABLE `%s` ADD COLUMN `user_agent` text NULL', $table);
        } elseif (stripos($adapter, 'SQLite') !== false) {
            $sql = sprintf('ALTER TABLE "%s" ADD COLUMN "user_agent" TEXT', $table);
        }

        if ($sql === null) {
            return;
        }

        try {
            $db->query($sql);
        } catch (\Exception $e) {
        }
    }

    private static function schemaScript(string $adapter): ?string
    {
        if (stripos($adapter, 'Mysql') !== false) {
            $content = file_get_contents(__DIR__ . '/sql/Mysql.sql');
            return $content === false ? null : $content;
        }
        if (stripos($adapter, 'SQLite') !== false) {
            $content = file_get_contents(__DIR__ . '/sql/SQLite.sql');
            return $content === false ? null : $content;
        }
        return null;
    }

    private static function upgrade_1_1_0_to_1_2_0(Db $db, string $adapter, string $prefix): void
    {
        if (self::tableExists($db, 'fail2ban_config')) {
            return;
        }

        $sql = null;
        if (stripos($adapter, 'Mysql') !== false) {
            $sql = sprintf(
                'CREATE TABLE `%sfail2ban_config` (
                    `id` int unsigned NOT NULL AUTO_INCREMENT,
                    `config` longtext NOT NULL,
                    `updated_at` int unsigned NOT NULL DEFAULT 0,
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
                $prefix
            );
        } elseif (stripos($adapter, 'SQLite') !== false) {
            $sql = sprintf(
                'CREATE TABLE "%sfail2ban_config" (
                    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
                    "config" TEXT NOT NULL,
                    "updated_at" INTEGER NOT NULL DEFAULT 0
                )',
                $prefix
            );
        }

        if ($sql !== null) {
            try {
                $db->query($sql);
            } catch (\Exception $e) {
            }
        }
    }

    private static function upgrade_1_2_0_to_1_3_0(Db $db, string $adapter, string $prefix): void
    {
        $indexName = $prefix . 'fail2ban_logs_created_ip';
        $table = $prefix . 'fail2ban_logs';

        if (self::indexExists($db, $adapter, $table, $indexName)) {
            return;
        }

        $sql = null;
        if (stripos($adapter, 'Mysql') !== false) {
            $sql = sprintf('ALTER TABLE `%s` ADD INDEX `%s` (`created_at`, `ip`)', $table, $indexName);
        } elseif (stripos($adapter, 'SQLite') !== false) {
            $sql = sprintf('CREATE INDEX IF NOT EXISTS "%s" ON "%s" ("created_at", "ip")', $indexName, $table);
        }

        if ($sql !== null) {
            try {
                $db->query($sql);
            } catch (\Exception $e) {
            }
        }
    }

    private static function tableExists(Db $db, string $table): bool
    {
        try {
            $db->fetchRow($db->select()->from('table.' . $table)->limit(1));
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    private static function columnExists(Db $db, string $adapter, string $table, string $column): bool
    {
        try {
            if (stripos($adapter, 'Mysql') !== false) {
                $sql = sprintf("SHOW COLUMNS FROM `%s` LIKE '%s'", $table, $column);
                $result = $db->query($sql, Db::READ);
                $row = $db->fetchRow($result);
                return !empty($row);
            }
            if (stripos($adapter, 'SQLite') !== false) {
                $sql = sprintf("PRAGMA table_info('%s')", $table);
                $result = $db->query($sql, Db::READ);
                while ($row = $db->fetchRow($result)) {
                    if (isset($row['name']) && strtolower((string) $row['name']) === strtolower($column)) {
                        return true;
                    }
                }
                return false;
            }
        } catch (\Exception $e) {
            return false;
        }
        return true;
    }

    private static function runSqlScripts(Db $db, string $script): void
    {
        $statements = array_filter(array_map('trim', explode(';', $script)));
        foreach ($statements as $statement) {
            if ($statement === '') {
                continue;
            }
            $db->query($statement);
        }
    }

    public static function backupConfig(array $config): void
    {
        $db = Db::get();
        try {
            $db->query($db->delete('table.fail2ban_config'));
            $db->query(
                $db->insert('table.fail2ban_config')->rows([
                    'id' => 1,
                    'config' => serialize($config),
                    'updated_at' => time()
                ])
            );
        } catch (\Exception $e) {
        }
    }

    public static function getBackupConfig(): ?array
    {
        $db = Db::get();
        try {
            $backup = $db->fetchRow(
                $db->select()
                    ->from('table.fail2ban_config')
                    ->order('updated_at', Db::SORT_DESC)
                    ->limit(1)
            );
        } catch (\Exception $e) {
            return null;
        }

        if (empty($backup) || empty($backup['config'])) {
            return null;
        }

        $settings = @unserialize($backup['config']);
        if (!is_array($settings)) {
            return null;
        }

        return $settings;
    }

    public static function clearConfigBackup(): void
    {
        $db = Db::get();
        try {
            $db->query($db->delete('table.fail2ban_config'));
        } catch (\Exception $e) {
        }
    }

    private static function indexExists(Db $db, string $adapter, string $table, string $index): bool
    {
        try {
            if (stripos($adapter, 'Mysql') !== false) {
                $sql = sprintf("SHOW INDEX FROM `%s` WHERE Key_name = '%s'", $table, $index);
                $result = $db->query($sql, Db::READ);
                $row = $db->fetchRow($result);
                return !empty($row);
            }
            if (stripos($adapter, 'SQLite') !== false) {
                $sql = sprintf("PRAGMA index_list('%s')", $table);
                $result = $db->query($sql, Db::READ);
                while ($row = $db->fetchRow($result)) {
                    if (isset($row['name']) && strtolower((string) $row['name']) === strtolower($index)) {
                        return true;
                    }
                }
                return false;
            }
        } catch (\Exception $e) {
            return false;
        }
        return false;
    }
}
