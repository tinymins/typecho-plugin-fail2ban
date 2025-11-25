CREATE TABLE "typecho_fail2ban_hits" (
  "id" INTEGER PRIMARY KEY AUTOINCREMENT,
  "ip" TEXT NOT NULL,
  "rule_pattern" TEXT NOT NULL,
  "rule_hash" TEXT NOT NULL,
  "last_path" TEXT NOT NULL,
  "first_seen" INTEGER NOT NULL DEFAULT 0,
  "last_seen" INTEGER NOT NULL DEFAULT 0,
  "counter" INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX "typecho_fail2ban_hits_ip_hash" ON "typecho_fail2ban_hits" ("ip", "rule_hash");
CREATE INDEX "typecho_fail2ban_hits_last_seen" ON "typecho_fail2ban_hits" ("last_seen");

CREATE TABLE "typecho_fail2ban_bans" (
  "id" INTEGER PRIMARY KEY AUTOINCREMENT,
  "ip" TEXT NOT NULL,
  "rule_pattern" TEXT NOT NULL,
  "rule_hash" TEXT NOT NULL,
  "reason" TEXT NOT NULL,
  "hits" INTEGER NOT NULL DEFAULT 0,
  "threshold" INTEGER NOT NULL DEFAULT 0,
  "window_size" INTEGER NOT NULL DEFAULT 0,
  "ban_length" INTEGER NOT NULL DEFAULT 0,
  "first_detected" INTEGER NOT NULL DEFAULT 0,
  "last_detected" INTEGER NOT NULL DEFAULT 0,
  "expires_at" INTEGER NOT NULL DEFAULT 0,
  "active" INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX "typecho_fail2ban_bans_ip_active" ON "typecho_fail2ban_bans" ("ip", "active");
CREATE INDEX "typecho_fail2ban_bans_expires" ON "typecho_fail2ban_bans" ("expires_at");

CREATE TABLE "typecho_fail2ban_logs" (
  "id" INTEGER PRIMARY KEY AUTOINCREMENT,
  "ip" TEXT NOT NULL,
  "path" TEXT NOT NULL,
  "rule_pattern" TEXT NOT NULL,
  "rule_hash" TEXT NOT NULL,
  "hits" INTEGER NOT NULL DEFAULT 0,
  "created_at" INTEGER NOT NULL DEFAULT 0,
  "message" TEXT NOT NULL,
  "user_agent" TEXT
);
CREATE INDEX "typecho_fail2ban_logs_created" ON "typecho_fail2ban_logs" ("created_at");
CREATE INDEX "typecho_fail2ban_logs_ip" ON "typecho_fail2ban_logs" ("ip");

CREATE TABLE "typecho_fail2ban_config" (
  "id" INTEGER PRIMARY KEY AUTOINCREMENT,
  "config" TEXT NOT NULL,
  "updated_at" INTEGER NOT NULL DEFAULT 0
);
