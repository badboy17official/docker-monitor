#!/bin/bash
# Bootstrap script: initializes database, creates admin user, sets up Redis cache

set -e

echo "🚀 DevSecOps Platform Bootstrap"
echo "========================================"

# Wait for PostgreSQL
echo "⏳ Waiting for PostgreSQL to be ready..."
until PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB -c "SELECT 1" 2>/dev/null; do
    echo "  PostgreSQL not ready yet, retrying..."
    sleep 2
done
echo "✅ PostgreSQL is ready"

# Wait for Redis
echo "⏳ Waiting for Redis to be ready..."
until redis-cli -h $REDIS_HOST -p $REDIS_PORT ping 2>/dev/null | grep -q PONG; do
    echo "  Redis not ready yet, retrying..."
    sleep 2
done
echo "✅ Redis is ready"

# Run SQL migrations
echo "📦 Applying database schema..."
PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB < /app/sql/schema.sql
echo "✅ Database schema applied"

# Create admin user (if using auth-service)
if [ -x "/app/scripts/seed_admin.py" ]; then
    echo "👤 Seeding admin user..."
    python /app/scripts/seed_admin.py
    echo "✅ Admin user created"
fi

echo ""
echo "✨ Bootstrap complete!"
echo "========================================"
echo "API Gateway:      http://localhost:8000"
echo "Dashboard:        http://localhost:3000"
echo "Health Check:     http://localhost:8000/health"
echo ""
echo "Default credentials:"
echo "  Email:    admin@devsecops.local"
echo "  Password: ChangeMe123!"
echo "  (Change immediately in production)"
