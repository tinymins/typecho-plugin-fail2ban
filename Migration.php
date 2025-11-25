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
        $table = $prefix . 'fail2ban_logs';

        if (!self::columnExists($db, $adapter, $table, 'user_agent')) {
            $sql = null;
            if (stripos($adapter, 'Mysql') !== false) {
                $sql = sprintf('ALTER TABLE `%s` ADD COLUMN `user_agent` text NULL', $table);
            } elseif (stripos($adapter, 'SQLite') !== false) {
                $sql = sprintf('ALTER TABLE "%s" ADD COLUMN "user_agent" TEXT', $table);
            }
            if ($sql !== null) {
                try {
                    $db->query($sql);
                } catch (\Exception $e) {
                }
            }
        }

        self::$schemaChecked = true;
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
}
