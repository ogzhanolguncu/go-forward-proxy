#!/bin/bash
set -e
echo "🚀 Deploying Go Proxy..."

# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker if not present
if ! command -v docker &>/dev/null; then
  echo "📦 Installing Docker..."
  curl -fsSL https://get.docker.com -o get-docker.sh
  sudo sh get-docker.sh
  sudo usermod -aG docker "$USER"
  rm get-docker.sh
  echo "⚠️  Docker installed. Please logout and login again, then re-run this script"
  exit 0
fi

# Install Docker Compose if not present
if ! command -v docker-compose &>/dev/null; then
  echo "📦 Installing Docker Compose..."
  sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  sudo chmod +x /usr/local/bin/docker-compose
fi

# Create directories
mkdir -p ssl

# Create filter files if they don't exist
if [ ! -f forbidden-hosts.txt ]; then
  echo "Creating forbidden-hosts.txt..."
  cat >forbidden-hosts.txt <<EOF
# Add blocked domains here
facebook.com
twitter.com
EOF
fi

if [ ! -f banned-words.txt ]; then
  echo "Creating banned-words.txt..."
  cat >banned-words.txt <<EOF
# Add banned words here
spam
malware
EOF
fi

# Generate self-signed SSL cert
if [ ! -f ssl/cert.pem ]; then
  echo "🔐 Generating self-signed SSL certificate..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout ssl/key.pem \
    -out ssl/cert.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
fi

# Set proper permissions
chmod 600 ssl/key.pem
chmod 644 ssl/cert.pem

# Stop existing containers
docker-compose down 2>/dev/null || true

# Build and start services
echo "🏗️  Building and starting services..."
docker-compose build
docker-compose up -d

# Wait for services
echo "⏳ Waiting for services to start..."
sleep 15

# Test deployment
echo "🧪 Testing deployment..."
if curl -k -f https://localhost/health &>/dev/null; then
  echo "✅ Deployment complete!"
  echo "🌐 Service available at: https://$(curl -s ifconfig.me)"
  echo "🏥 Health check: https://$(curl -s ifconfig.me)/health"
  echo "📊 View logs: docker-compose logs -f"
else
  echo "❌ Health check failed. Checking logs..."
  docker-compose logs
  exit 1
fi
