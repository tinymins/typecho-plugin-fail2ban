<?php
if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

use Typecho\Db;
use Typecho\Date;
use Typecho\Db\Exception as DbException;
use Utils\Helper;
use Widget\Security;

require_once __TYPECHO_ROOT_DIR__ . __TYPECHO_ADMIN_DIR__ . '/common.php';
require_once __TYPECHO_ROOT_DIR__ . __TYPECHO_ADMIN_DIR__ . '/header.php';
require_once __TYPECHO_ROOT_DIR__ . __TYPECHO_ADMIN_DIR__ . '/menu.php';

$db = Db::get();
$security = Helper::security();
$actionUrl = $security->getIndex('action/' . \TypechoPlugin\Fail2ban\Plugin::$action);

try {
    $activeBans = $db->fetchAll(
        $db->select()
            ->from('table.fail2ban_bans')
            ->where('active = ?', 1)
            ->order('last_detected', Db::SORT_DESC)
    );
} catch (DbException $e) {
    $activeBans = [];
    $bansError = $e->getMessage();
}

$banLogs = [];
$banUserAgents = [];
if (!empty($activeBans)) {
    $ips = array_unique(array_map(static fn($ban) => $ban['ip'], $activeBans));
    try {
        $logQuery = $db->select()
            ->from('table.fail2ban_logs')
            ->where('ip IN ?', $ips)
            ->order('created_at', Db::SORT_DESC)
            ->limit(count($ips) * 10);
        $rows = $db->fetchAll($logQuery);
        foreach ($rows as $row) {
            $ip = $row['ip'];
            if (!isset($banLogs[$ip])) {
                $banLogs[$ip] = [];
            }
            $logUserAgent = isset($row['user_agent']) ? trim((string) $row['user_agent']) : '';
            if ($logUserAgent === '') {
                $logUserAgent = null;
            }

            if (!isset($banUserAgents[$ip]) && $logUserAgent !== null) {
                $banUserAgents[$ip] = $logUserAgent;
            }
            if (count($banLogs[$ip]) >= 5) {
                continue;
            }
            $path = $row['path'];
            $timestamp = (int) $row['created_at'];
            $duplicate = false;
            foreach ($banLogs[$ip] as $entry) {
                if ($entry['path'] === $path && $entry['time'] === $timestamp) {
                    $duplicate = true;
                    break;
                }
            }
            if (!$duplicate) {
                $banLogs[$ip][] = [
                    'path' => $path,
                    'time' => $timestamp,
                    'user_agent' => $logUserAgent
                ];
            }
        }
    } catch (DbException $e) {
        $banLogs = [];
    }
}

try {
    $recentLogs = $db->fetchAll(
        $db->select()
            ->from('table.fail2ban_logs')
            ->order('id', Db::SORT_DESC)
            ->limit(20)
    );
} catch (DbException $e) {
    $recentLogs = [];
    $logsError = $e->getMessage();
}

$options = Helper::options();
$pluginConfig = $options->plugin('Fail2ban');
$timezoneOffset = $options->timezone - $options->serverTimezone;
$now = (int) ($options->gmtTime + $timezoneOffset);
$since24Hours = max(0, $now - 86400);

$stats = [
    'activeIps' => !empty($activeBans) ? count($activeBans) : 0,
    'ips24h' => 0,
    'intercepts24h' => 0,
    'totalIntercepts' => 0,
    'totalIpsEver' => 0
];
$statsErrors = [];

try {
    $row = $db->fetchRow(
        $db->select('COUNT(*) AS total_hits', 'COUNT(DISTINCT ip) AS unique_ips')
            ->from('table.fail2ban_logs')
            ->where('created_at >= ?', $since24Hours)
    );
    if ($row) {
        if (isset($row['unique_ips'])) {
            $stats['ips24h'] = (int) $row['unique_ips'];
        }
        if (isset($row['total_hits'])) {
            $stats['intercepts24h'] = (int) $row['total_hits'];
        }
    }
} catch (DbException $e) {
    $statsErrors[] = $e->getMessage();
}

try {
    $row = $db->fetchRow(
        $db->select('COUNT(*) AS total_hits', 'COUNT(DISTINCT ip) AS unique_ips')
            ->from('table.fail2ban_logs')
    );
    if ($row) {
        if (isset($row['unique_ips'])) {
            $stats['totalIpsEver'] = (int) $row['unique_ips'];
        }
        if (isset($row['total_hits'])) {
            $stats['totalIntercepts'] = (int) $row['total_hits'];
        }
    }
} catch (DbException $e) {
    $statsErrors[] = $e->getMessage();
}

if (!empty($statsErrors)) {
    $statsErrors = array_values(array_unique($statsErrors));
}
?>
<div class="main">
    <div class="body container">
        <div class="typecho-page-title">
            <h2><?php _e('Fail2ban 防护概览'); ?></h2>
        </div>
        <div class="row typecho-page-main" role="main">
            <div class="col-mb-12 typecho-list">
                <p><?php _e('当前状态：%s', $pluginConfig->enabled === '0' ? '<span class="warning">' . _t('已停用') . '</span>' : '<span class="success">' . _t('运行中') . '</span>'); ?></p>
                <p><?php _e('默认规则窗口 %s 分钟，触发阈值 %s 次，封禁 %s 分钟。',
                    intval($pluginConfig->windowMinutes ?: 5),
                    intval($pluginConfig->thresholdHits ?: 5),
                    intval($pluginConfig->banMinutes ?: 60)
                ); ?></p>
                <?php if (!empty($statsErrors)): ?>
                    <p class="error"><?php echo htmlspecialchars(implode('; ', $statsErrors)); ?></p>
                <?php endif; ?>
                <p><?php _e('封禁统计：当前封禁 IP %d 个；24 小时内封禁 IP %d 个，拦截访问 %d 次；累计拦截访问 %d 次，累计封禁 IP %d 个。',
                    (int) $stats['activeIps'],
                    (int) $stats['ips24h'],
                    (int) $stats['intercepts24h'],
                    (int) $stats['totalIntercepts'],
                    (int) $stats['totalIpsEver']
                ); ?></p>
            </div>
            <div class="col-mb-12">
                <h3><?php _e('正在阻止的 IP'); ?></h3>
                <p class="description"><?php _e('命中规则的 IP 会在这里列出，可以根据需要手动解除。'); ?></p>
                <div class="typecho-table-wrap">
                    <table class="typecho-list-table">
                        <colgroup>
                            <col style="width:20%">
                            <col>
                            <col style="width:12%">
                        </colgroup>
                        <thead>
                            <tr>
                                <th><?php _e('基础信息'); ?></th>
                                <th><?php _e('规则日志'); ?></th>
                                <th><?php _e('操作'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php if (!empty($bansError)): ?>
                            <tr><td colspan="5" class="error"><?php echo htmlspecialchars($bansError); ?></td></tr>
                        <?php elseif (empty($activeBans)): ?>
                            <tr><td colspan="5"><?php _e('当前没有正在生效的封禁。'); ?></td></tr>
                        <?php else: ?>
                            <?php foreach ($activeBans as $ban): ?>
                                <?php
                                    $expires = new Date((int) $ban['expires_at']);
                                    $lastDetected = new Date((int) $ban['last_detected']);
                                    $ipUserAgent = isset($banUserAgents[$ban['ip']]) ? $banUserAgents[$ban['ip']] : null;
                                ?>
                                <tr>
                                    <td>
                                        <strong<?php if (!empty($ipUserAgent)): ?> title="<?php echo htmlspecialchars($ipUserAgent, ENT_QUOTES, 'UTF-8'); ?>"<?php endif; ?>><?php echo htmlspecialchars($ban['ip']); ?></strong><br>
                                        <small><?php _e('最后检测：%s', $lastDetected->format('Y-m-d H:i:s')); ?></small><br>
                                        <small><?php _e('解除时间：%s', $expires->format('Y-m-d H:i:s')); ?></small><br>
                                        <small><?php _e('封禁时长：%d 分钟', max(1, (int) $ban['ban_length'])); ?></small>
                                    </td>
                                    <td>
                                        <code><?php echo htmlspecialchars($ban['rule_pattern']); ?></code><br>
                                        <small>
                                            <?php _e('%1$d 分钟窗口内命中 %2$d/%3$d 次',
                                                max(1, (int) $ban['window_size']),
                                                (int) $ban['hits'],
                                                max(1, (int) $ban['threshold'])
                                            ); ?>
                                        </small>
                                        <?php if (!empty($banLogs[$ban['ip']])): ?>
                                            <?php foreach ($banLogs[$ban['ip']] as $logEntry): ?>
                                                <?php $logTime = new Date($logEntry['time']); ?>
                                                <div>
                                                    <code><?php echo htmlspecialchars($logEntry['path']); ?></code>
                                                    <small><?php echo $logTime->format('Y-m-d H:i:s'); ?></small>
                                                </div>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <form method="post" action="<?php echo $actionUrl; ?>" class="inline">
                                            <input type="hidden" name="do" value="unban">
                                            <input type="hidden" name="banId" value="<?php echo (int) $ban['id']; ?>">
                                            <button type="submit" class="btn btn-link"><?php _e('解除封禁'); ?></button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>
                <form method="post" action="<?php echo $actionUrl; ?>" class="inline">
                    <input type="hidden" name="do" value="flush">
                    <button type="submit" class="btn primary"><?php _e('手动清理已过期封禁'); ?></button>
                </form>
            </div>

            <div class="col-mb-12">
                <h3><?php _e('最近封禁日志'); ?></h3>
                <div class="typecho-table-wrap">
                    <table class="typecho-list-table">
                        <colgroup>
                            <col width="20%">
                            <col width="20%">
                            <col width="20%">
                            <col width="40%">
                        </colgroup>
                        <thead>
                            <tr>
                                <th><?php _e('时间'); ?></th>
                                <th><?php _e('IP'); ?></th>
                                <th><?php _e('规则'); ?></th>
                                <th><?php _e('详情'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php if (!empty($logsError)): ?>
                            <tr><td colspan="4" class="error"><?php echo htmlspecialchars($logsError); ?></td></tr>
                        <?php elseif (empty($recentLogs)): ?>
                            <tr><td colspan="4"><?php _e('暂无记录。'); ?></td></tr>
                        <?php else: ?>
                            <?php foreach ($recentLogs as $log): ?>
                                <?php $created = new Date((int) $log['created_at']); ?>
                                <tr>
                                    <td><?php echo $created->format('Y-m-d H:i:s'); ?></td>
                                    <td><?php echo htmlspecialchars($log['ip']); ?></td>
                                    <td><code><?php echo htmlspecialchars($log['rule_pattern']); ?></code></td>
                                    <td>
                                        <div><?php echo htmlspecialchars($log['message']); ?></div>
                                        <small><?php _e('请求：%s', htmlspecialchars($log['path'])); ?></small>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<?php
require_once __TYPECHO_ROOT_DIR__ . __TYPECHO_ADMIN_DIR__ . '/footer.php';
?>
