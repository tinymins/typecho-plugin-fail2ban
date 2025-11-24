<?php

namespace TypechoPlugin\Fail2ban;

use Typecho\Db;
use Typecho\Plugin as TypechoPlugin;
use Typecho\Plugin\PluginInterface;
use Typecho\Plugin\Exception as PluginException;
use Typecho\Widget\Helper\Form;
use Typecho\Widget\Helper\Form\Element\Radio;
use Typecho\Widget\Helper\Form\Element\Textarea;
use Typecho\Widget\Helper\Form\Element\Text;
use Utils\Helper;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

require_once __DIR__ . '/Guard.php';
require_once __DIR__ . '/Action.php';
require_once __DIR__ . '/Api.php';

/**
 * Fail2ban 风格的防护插件，为 Typecho 按规则封禁恶意请求。
 *
 * @package Fail2ban
 * @author 茗伊
 * @version 1.0.0
 * @link https://zhaiyiming.com/
 */
class Plugin implements PluginInterface
{
    public static string $panel = 'Fail2ban/page/console.php';
    public static string $action = 'fail2ban';

    public static function activate(): string
    {
        self::install();
        Helper::addAction(self::$action, 'TypechoPlugin\\Fail2ban\\Action');
        Helper::addPanel(1, self::$panel, _t('Fail2ban防护'), _t('Fail2ban 防护控制台'), 'administrator');
        TypechoPlugin::factory('Widget_Archive')->beforeRender = [Guard::class, 'handle'];
        return _t('Fail2ban 已启用。');
    }

    public static function deactivate(): void
    {
        Helper::removeAction(self::$action);
        Helper::removePanel(1, self::$panel);

        $config = Helper::options()->plugin('Fail2ban');
        if (!empty($config->dropOnDeactivate) && $config->dropOnDeactivate === '1') {
            self::dropTables();
        }
    }

    public static function config(Form $form): void
    {
        $enabled = new Radio('enabled', [
            '1' => _t('开启'),
            '0' => _t('关闭'),
        ], '1', _t('启用防护'), _t('关闭后插件将不再拦截任何请求。'));

        $rules = new Textarea('rules', null, self::getDefaultRules(),
            _t('检测规则'),
            _t('每行一条规则，格式：<code>模式|窗口(分钟)|阈值(次数)|封禁时长(分钟)</code>。支持前缀 <code>regex:</code> 使用正则匹配。以 <code>#</code> 开头的行会被忽略。'));
        $rules->setAttribute('rows', 8);

        $window = new Text('windowMinutes', null, '5', _t('默认检测窗口 (分钟)'), _t('当单条规则没有指定窗口时使用。'));
        $window->addRule('isInteger', _t('请填写数字'))->addRule([__CLASS__, 'validatePositiveInt'], _t('必须为正整数'));

        $threshold = new Text('thresholdHits', null, '5', _t('默认阈值 (次)'), _t('当单条规则没有指定命中次数时使用。'));
        $threshold->addRule('isInteger', _t('请填写数字'))->addRule([__CLASS__, 'validatePositiveInt'], _t('必须为正整数'));

        $ban = new Text('banMinutes', null, '60', _t('默认封禁时长 (分钟)'), _t('当单条规则没有指定封禁时长时使用。'));
        $ban->addRule('isInteger', _t('请填写数字'))->addRule([__CLASS__, 'validatePositiveInt'], _t('必须为正整数'));

        $whitelist = new Textarea('whitelist', null, '', _t('白名单 IP / 网段'), _t('每行一个 IP 或 CIDR，例如 <code>127.0.0.1</code> 或 <code>192.168.0.0/24</code>。匹配的请求将跳过检测。'));
        $whitelist->setAttribute('rows', 4);

        $denyMessage = new Textarea('denyMessage', null, 'Access denied.', _t('拒绝访问提示'), _t('当请求被阻止时返回的响应文本，支持 HTML。'));
        $denyMessage->setAttribute('rows', 2);

        $drop = new Radio('dropOnDeactivate', [
            '0' => _t('保留'),
            '1' => _t('删除'),
        ], '0', _t('停用时是否删除数据表'), _t('选中“删除”将在停用插件时移除所有 Fail2ban 数据表。'));

        $form->addInput($enabled);
        $form->addInput($rules);
        $form->addInput($window);
        $form->addInput($threshold);
        $form->addInput($ban);
        $form->addInput($whitelist);
        $form->addInput($denyMessage);
        $form->addInput($drop);
    }

    public static function personalConfig(Form $form): void
    {
    }

    public static function getDefaultRules(): string
    {
        return implode("\n", [
            '# Wordpress 探测',
            'regex:^/(wp-admin|wp-content|wp-includes|wp-json|wp-login\\.php)|3|4|180',
            '# 重复 index.php 路径',
            'regex:^/index\\.php/(?:index\\.php/){2,}|2|2|240',
            '# 敏感文件探测',
            'regex:(?:/\\.env$|/\\.git|/phpinfo\\.php|/phpMyAdmin)|10|1|1440'
        ]);
    }

    public static function validatePositiveInt($value): bool
    {
        return (int) $value > 0;
    }

    private static function install(): void
    {
        $db = Db::get();
        $adapterName = $db->getAdapterName();
        $prefix = $db->getPrefix();

        if (self::tableExists($db, 'fail2ban_hits')) {
            return;
        }

        if (stripos($adapterName, 'Mysql') !== false) {
            $scripts = file_get_contents(__DIR__ . '/sql/Mysql.sql');
            $scripts = str_replace('typecho_', $prefix, $scripts);
            self::runSqlScripts($db, $scripts);
        } elseif (stripos($adapterName, 'SQLite') !== false) {
            $scripts = file_get_contents(__DIR__ . '/sql/SQLite.sql');
            $scripts = str_replace('typecho_', $prefix, $scripts);
            self::runSqlScripts($db, $scripts);
        } else {
            throw new PluginException(_t('Fail2ban 暂不支持当前数据库适配器: %s', $adapterName));
        }
    }

    private static function dropTables(): void
    {
        $db = Db::get();
        foreach (['fail2ban_hits', 'fail2ban_bans', 'fail2ban_logs'] as $table) {
            try {
                $db->query(sprintf('DROP TABLE IF EXISTS `%s%s`', $db->getPrefix(), $table));
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
