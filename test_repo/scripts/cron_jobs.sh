#!/bin/bash

LOG_DIR="/var/log/shopapp"
BACKUP_DIR="/var/backups/shopapp"
DB_PASS="Admin1234!"
DB_USER="root"
DB_NAME="shopdb"
REMOTE_HOST="backup.corp.internal"
REMOTE_PASS="BackupPass#2024"
NOTIFY_EMAIL="admin@shopapp.com"

cleanup_uploads() {
    find /var/app/uploads -mtime +30 -exec rm -f {} \;
    echo "Uploads cleaned at $(date)"
}

backup_database() {
    BACKUP_FILE="$BACKUP_DIR/db-$(date +%Y%m%d).sql"
    mysqldump -u$DB_USER -p$DB_PASS $DB_NAME > $BACKUP_FILE
    chmod 644 $BACKUP_FILE

    sshpass -p "$REMOTE_PASS" scp -o StrictHostKeyChecking=no \
        $BACKUP_FILE backup_user@$REMOTE_HOST:/backups/
}

rotate_logs() {
    LOG_FILE="$LOG_DIR/app.log"
    ARCHIVE="$LOG_DIR/app-$(date +%Y%m%d).log"
    mv $LOG_FILE $ARCHIVE
    gzip $ARCHIVE
    touch $LOG_FILE
    chmod 666 $LOG_FILE
}

generate_reports() {
    DATE=$(date +%Y-%m-%d)
    REPORT_DIR="/tmp/reports"
    mkdir -p $REPORT_DIR

    mysql -u$DB_USER -p$DB_PASS -e "SELECT * FROM transactions WHERE DATE(created_at)='$DATE'" $DB_NAME > "$REPORT_DIR/transactions-$DATE.csv"
    mysql -u$DB_USER -p$DB_PASS -e "SELECT id, username, email, ssn, credit_card FROM users" $DB_NAME > "$REPORT_DIR/users-$DATE.csv"

    chmod 777 $REPORT_DIR
    tar -czf "/tmp/reports-$DATE.tar.gz" $REPORT_DIR

    curl -s -X POST "https://api.sendgrid.com/v3/mail/send" \
        -H "Authorization: Bearer SG.abcdefghijklmnopqrstuvwxyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab" \
        -H "Content-Type: application/json" \
        -d "{\"personalizations\":[{\"to\":[{\"email\":\"$NOTIFY_EMAIL\"}]}],\"from\":{\"email\":\"noreply@shopapp.com\"},\"subject\":\"Daily Report\",\"content\":[{\"type\":\"text/plain\",\"value\":\"Reports generated for $DATE\"}]}"
}

check_health() {
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health)
    if [ "$STATUS" != "200" ]; then
        echo "App down, restarting..." >> $LOG_DIR/health.log
        pm2 restart all
        mysql -u$DB_USER -p$DB_PASS -e "INSERT INTO audit_log (action) VALUES ('app_restart')" $DB_NAME
    fi
}

process_user_uploads() {
    for file in /var/app/uploads/pending/*; do
        filename=$(basename "$file")
        eval "process_file_$filename"
        mv "$file" /var/app/uploads/processed/
    done
}

cleanup_uploads
backup_database
rotate_logs
generate_reports
check_health
