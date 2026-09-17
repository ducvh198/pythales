#!/usr/bin/env bash
# ==============================================================================
# PyThales HSM Simulator - Docker Build & Push Script
# Registry: registry.hevitech.io.vn
# ==============================================================================

set -eo pipefail

REGISTRY="${REGISTRY:-registry.hevitech.io.vn}"
IMAGE_NAME="${IMAGE_NAME:-pythales}"
TAG="${TAG:-latest}"
PLATFORM="${PLATFORM:-linux/amd64}"
NO_PUSH=false
SKIP_TESTS=false
ADDITIONAL_TAGS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--registry)
      REGISTRY="$2"
      shift 2
      ;;
    -i|--image)
      IMAGE_NAME="$2"
      shift 2
      ;;
    -t|--tag)
      TAG="$2"
      shift 2
      ;;
    --additional-tag)
      ADDITIONAL_TAGS+=("$2")
      shift 2
      ;;
    -p|--platform)
      PLATFORM="$2"
      shift 2
      ;;
    --no-push)
      NO_PUSH=true
      shift
      ;;
    --skip-tests)
      SKIP_TESTS=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  -r, --registry REGISTRY     Docker registry (default: registry.hevitech.io.vn)"
      echo "  -i, --image IMAGE           Image repository name (default: pythales)"
      echo "  -t, --tag TAG               Primary tag (default: latest)"
      echo "  --additional-tag TAG        Additional tag (can be used multiple times)"
      echo "  -p, --platform PLATFORM     Target platform (default: linux/amd64)"
      echo "  --no-push                   Build only, do not push to registry"
      echo "  --skip-tests                Skip automated tests before build"
      echo "  -h, --help                  Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}==> Detecting repository root...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT=""

for dir in "$SCRIPT_DIR" "$SCRIPT_DIR/.." "$(pwd)" "$(pwd)/.."; do
  if [[ -f "$dir/Dockerfile" ]]; then
    REPO_ROOT="$(cd "$dir" && pwd)"
    break
  fi
done

if [[ -z "$REPO_ROOT" ]]; then
  echo -e "${RED}[ERROR] Could not locate 'Dockerfile'.${NC}"
  exit 1
fi

DOCKERFILE="$REPO_ROOT/Dockerfile"
echo "Repository Root: $REPO_ROOT"
echo "Dockerfile:      $DOCKERFILE"

# Check docker
if ! command -v docker &> /dev/null; then
  echo -e "${RED}[ERROR] 'docker' command not found. Please install Docker.${NC}"
  exit 1
fi

if ! docker info &> /dev/null; then
  echo -e "${RED}[ERROR] Docker daemon is not running.${NC}"
  echo -e "${YELLOW}Please start Docker daemon / Docker Desktop and try again.${NC}"
  exit 1
fi

# Run tests
if [ "$SKIP_TESTS" = false ]; then
  echo -e "${CYAN}==> Running automated tests...${NC}"
  if [[ -f "$REPO_ROOT/.venv/bin/pytest" ]]; then
    (cd "$REPO_ROOT" && "$REPO_ROOT/.venv/bin/pytest" tests test_hmac_suite.py)
  elif command -v pytest &> /dev/null; then
    (cd "$REPO_ROOT" && pytest tests test_hmac_suite.py)
  else
    echo -e "${YELLOW}[WARNING] pytest not found, skipping tests.${NC}"
  fi
fi

# Resolve tags
TAGS=("$TAG")

# Add git sha tag if available
if command -v git &> /dev/null; then
  GIT_SHA=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || true)
  if [[ -n "$GIT_SHA" ]]; then
    TAGS+=("sha-$GIT_SHA")
  fi
fi

for extra in "${ADDITIONAL_TAGS[@]}"; do
  TAGS+=("$extra")
done

FULL_IMAGE_BASE="${REGISTRY}/${IMAGE_NAME}"
PRIMARY_IMAGE="${FULL_IMAGE_BASE}:${TAGS[0]}"

echo -e "${CYAN}==> Building Docker image for platform $PLATFORM: $PRIMARY_IMAGE ...${NC}"
docker build --platform "$PLATFORM" -t "$PRIMARY_IMAGE" -f "$DOCKERFILE" "$REPO_ROOT"
echo -e "${GREEN}[SUCCESS] Image built successfully: $PRIMARY_IMAGE${NC}"

# Tag additional
for ((i=1; i<${#TAGS[@]}; i++)); do
  EXTRA_URI="${FULL_IMAGE_BASE}:${TAGS[i]}"
  echo "Tagging: $EXTRA_URI"
  docker tag "$PRIMARY_IMAGE" "$EXTRA_URI"
done

# Push
if [ "$NO_PUSH" = false ]; then
  echo -e "${CYAN}==> Pushing image(s) to $REGISTRY ...${NC}"
  for t in "${TAGS[@]}"; do
    PUSH_URI="${FULL_IMAGE_BASE}:${t}"
    echo "Pushing: $PUSH_URI"
    docker push "$PUSH_URI"
    echo -e "${GREEN}[SUCCESS] Pushed $PUSH_URI${NC}"
  done
  echo -e "${GREEN}[SUCCESS] All images pushed successfully to $REGISTRY!${NC}"
  echo ""
  echo -e "${CYAN}Pull command:${NC}"
  echo "  docker pull $PRIMARY_IMAGE"
  echo -e "${CYAN}Run command:${NC}"
  echo "  docker run -d -p 1500:1500 --name pythales-hsm $PRIMARY_IMAGE"
else
  echo -e "${YELLOW}[INFO] --no-push was specified. Images are kept locally.${NC}"
fi
