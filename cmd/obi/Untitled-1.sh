

docker buildx build \
  --platform linux/amd64 \
  --build-arg RELEASE_VERSION=ntest \
  --build-arg RELEASE_REVISION=ntest \
  -t ghcr.io/middleware-labs/ruby-app:ntest \
  --push \
  .
