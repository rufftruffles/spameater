# SpamEater Docker Makefile
# Convenience commands for Docker operations

.PHONY: help build up down restart logs shell status clean backup restore test

# Default target
help:
	@echo "SpamEater Docker Management Commands"
	@echo "===================================="
	@echo "  make build       - Build the Docker image"
	@echo "  make up          - Start all services"
	@echo "  make down        - Stop all services"
	@echo "  make restart     - Restart all services"
	@echo "  make logs        - View logs (follow mode)"
	@echo "  make shell       - Enter container shell"
	@echo "  make status      - Show service status"
	@echo "  make clean       - Remove containers and images"
	@echo "  make backup      - Backup data and certificates"
	@echo "  make restore     - Restore from backup"
	@echo "  make test        - Run health checks"
	@echo ""
	@echo "Advanced Commands:"
	@echo "  make ssl-renew   - Manually renew SSL certificates"
	@echo "  make db-check    - Check database integrity"
	@echo "  make security    - View security events"
	@echo "  make stats       - Show usage statistics"

# Build the Docker image
build:
	@echo "🔨 Building SpamEater Docker image..."
	docker compose build --no-cache

# Start services
up:
	@echo "🚀 Starting SpamEater..."
	@if [ ! -f .env ]; then \
		echo "❌ ERROR: .env file not found!"; \
		echo "   Run: cp .env.example .env"; \
		exit 1; \
	fi
	@mkdir -p data logs
	docker compose up -d
	@echo "✅ SpamEater is running!"
	@echo "   Web UI: https://$$(grep EMAIL_DOMAIN .env | cut -d= -f2)"
	@echo "   Logs: make logs"

# Stop services
down:
	@echo "🛑 Stopping SpamEater..."
	docker compose down

# Restart services
restart:
	@echo "🔄 Restarting SpamEater..."
	docker compose restart

# View logs
logs:
	docker compose logs -f --tail=100

# Enter container shell
shell:
	@echo "🐚 Entering SpamEater container..."
	docker exec -it spameater bash

# Show service status
status:
	@echo "📊 SpamEater Service Status"
	@echo "=========================="
	@docker compose ps
	@echo ""
	@echo "Internal Services:"
	@docker exec spameater supervisorctl status 2>/dev/null || echo "Container not running"

# Clean up everything
clean:
	@echo "🧹 Cleaning up SpamEater..."
	@read -p "⚠️  This will remove containers and images. Continue? (y/N) " confirm; \
	if [ "$$confirm" = "y" ]; then \
		docker compose down -v; \
		docker rmi $$(docker images -q spameater:* 2>/dev/null) 2>/dev/null || true; \
		echo "✅ Cleanup complete"; \
	else \
		echo "❌ Cleanup cancelled"; \
	fi

# Backup data
backup:
	@echo "💾 Creating backup..."
	@mkdir -p backups
	@BACKUP_DATE=$$(date +%Y%m%d-%H%M%S); \
	echo "Backing up data..."; \
	docker run --rm -v spameater_data:/data -v $$(pwd)/backups:/backup alpine \
		tar czf /backup/data-$$BACKUP_DATE.tar.gz -C /data . && \
	echo "Backing up certificates..."; \
	docker run --rm -v letsencrypt_certs:/certs -v $$(pwd)/backups:/backup alpine \
		tar czf /backup/certs-$$BACKUP_DATE.tar.gz -C /certs . 2>/dev/null || echo "No certificates to backup"; \
	echo "✅ Backup complete: backups/*-$$BACKUP_DATE.tar.gz"

# Restore from backup
restore:
	@echo "📥 Available backups:"
	@ls -1 backups/*.tar.gz 2>/dev/null || echo "No backups found"
	@read -p "Enter backup date (YYYYMMDD-HHMMSS): " BACKUP_DATE; \
	if [ -f "backups/data-$$BACKUP_DATE.tar.gz" ]; then \
		echo "Restoring data..."; \
		docker run --rm -v spameater_data:/data -v $$(pwd)/backups:/backup alpine \
			tar xzf /backup/data-$$BACKUP_DATE.tar.gz -C /data && \
		echo "✅ Data restored"; \
	else \
		echo "❌ Backup not found"; \
	fi; \
	if [ -f "backups/certs-$$BACKUP_DATE.tar.gz" ]; then \
		echo "Restoring certificates..."; \
		docker run --rm -v letsencrypt_certs:/certs -v $$(pwd)/backups:/backup alpine \
			tar xzf /backup/certs-$$BACKUP_DATE.tar.gz -C /certs && \
		echo "✅ Certificates restored"; \
	fi

# Test health
test:
	@echo "🏥 Running health checks..."
	@echo -n "Container: "
	@docker compose ps --format "table {{.Status}}" | tail -n 1
	@echo -n "API Health: "
	@docker exec spameater curl -s http://localhost:3001/api/health | grep -o '"status":"[^"]*"' || echo "Failed"
	@echo -n "Nginx: "
	@docker exec spameater nginx -t 2>&1 | grep -o "test is successful" || echo "Failed"
	@echo -n "Database: "
	@docker exec spameater sqlite3 /opt/spameater/data/emails.db ".tables" > /dev/null 2>&1 && echo "OK" || echo "Failed"

# Renew SSL certificates manually
ssl-renew:
	@echo "🔒 Renewing SSL certificates..."
	docker exec spameater certbot renew
	docker exec spameater nginx -s reload

# Check database
db-check:
	@echo "🗄️ Database Information"
	@echo "====================="
	@docker exec spameater sqlite3 /opt/spameater/data/emails.db \
		"SELECT 'Inboxes: ' || COUNT(*) FROM inboxes; \
		 SELECT 'Emails: ' || COUNT(*) FROM emails; \
		 SELECT 'Security Events: ' || COUNT(*) FROM security_events;"

# View security events
security:
	@echo "🛡️ Recent Security Events"
	@echo "======================="
	@docker exec spameater sqlite3 -column -header /opt/spameater/data/emails.db \
		"SELECT datetime(timestamp, 'unixepoch') as time, event_type, ip_address \
		 FROM security_events \
		 ORDER BY timestamp DESC \
		 LIMIT 20;"

# Show statistics
stats:
	@echo "📈 SpamEater Statistics"
	@echo "====================="
	@docker exec spameater sqlite3 -column /opt/spameater/data/emails.db \
		"SELECT 'Active Inboxes' as metric, COUNT(DISTINCT inbox_id) as count \
		 FROM emails WHERE received_at > strftime('%s', 'now', '-1 hour') \
		 UNION ALL \
		 SELECT 'Emails (24h)', COUNT(*) FROM emails \
		 WHERE received_at > strftime('%s', 'now', '-24 hours') \
		 UNION ALL \
		 SELECT 'Total Emails', COUNT(*) FROM emails \
		 UNION ALL \
		 SELECT 'Avg Size (KB)', ROUND(AVG(size_bytes)/1024.0, 2) FROM emails;"
