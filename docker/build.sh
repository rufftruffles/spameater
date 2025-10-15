#!/bin/bash
# SpamEater Docker Build Script
# Simple script to build the Docker image locally

set -e

echo "🍽️ SpamEater Docker Build"
echo "========================"

# Check if we're in the right directory
if [ ! -f "Dockerfile" ]; then
    echo "❌ ERROR: Dockerfile not found!"
    echo "   Please run this script from the docker/ directory"
    exit 1
fi

# Get version from git tag or use 'latest'
VERSION=$(git describe --tags --always 2>/dev/null || echo "latest")
IMAGE_NAME="spameater"

echo "📦 Building Docker image..."
echo "   Version: $VERSION"
echo ""

# Build the image
docker build \
    --tag "${IMAGE_NAME}:${VERSION}" \
    --tag "${IMAGE_NAME}:latest" \
    --file Dockerfile \
    --build-arg BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --build-arg VERSION="$VERSION" \
    ..

echo ""
echo "✅ Build complete!"
echo ""
echo "📋 Image Details:"
docker images | grep "^${IMAGE_NAME}" | head -2
echo ""
echo "🚀 To run the container:"
echo "   docker run -d \\"
echo "     -p 25:25 -p 80:80 -p 443:443 \\"
echo "     -e EMAIL_DOMAIN=your-domain.com \\"
echo "     --name spameater \\"
echo "     ${IMAGE_NAME}:${VERSION}"
echo ""
echo "📊 Or use docker-compose:"
echo "   docker compose up -d"
