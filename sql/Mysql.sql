CREATE TABLE `typecho_fail2ban_hits` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `ip` varchar(45) NOT NULL,
  `rule_pattern` varchar(255) NOT NULL,
  `rule_hash` char(32) NOT NULL,
  `last_path` text NOT NULL,
  `first_seen` int unsigned NOT NULL DEFAULT 0,
  `last_seen` int unsigned NOT NULL DEFAULT 0,
  `counter` int unsigned NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `ip_hash` (`ip`, `rule_hash`),
  KEY `last_seen` (`last_seen`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `typecho_fail2ban_bans` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `ip` varchar(45) NOT NULL,
  `rule_pattern` varchar(255) NOT NULL,
  `rule_hash` char(32) NOT NULL,
  `reason` varchar(255) NOT NULL,
  `hits` int unsigned NOT NULL DEFAULT 0,
  `threshold` int unsigned NOT NULL DEFAULT 0,
  `window_size` int unsigned NOT NULL DEFAULT 0,
  `ban_length` int unsigned NOT NULL DEFAULT 0,
  `first_detected` int unsigned NOT NULL DEFAULT 0,
  `last_detected` int unsigned NOT NULL DEFAULT 0,
  `expires_at` int unsigned NOT NULL DEFAULT 0,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `ip_active` (`ip`, `active`),
  KEY `expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `typecho_fail2ban_logs` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `ip` varchar(45) NOT NULL,
  `path` text NOT NULL,
  `rule_pattern` varchar(255) NOT NULL,
  `rule_hash` char(32) NOT NULL,
  `hits` int unsigned NOT NULL DEFAULT 0,
  `created_at` int unsigned NOT NULL DEFAULT 0,
  `message` varchar(255) NOT NULL,
  `user_agent` text,
  PRIMARY KEY (`id`),
  KEY `created_at` (`created_at`),
  KEY `ip` (`ip`),
  KEY `typecho_fail2ban_logs_created_ip` (`created_at`, `ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `typecho_fail2ban_config` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `config` longtext NOT NULL,
  `updated_at` int unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
