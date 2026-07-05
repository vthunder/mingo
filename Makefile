# Mingo reference implementation — deploy targets.
#
# Both prod apps live on the dokku host (sandmill.org) and build from THIS repo's
# root with an app-specific Dockerfile (set once via dokku builder-dockerfile:set,
# see DEPLOYMENT.md). Deploys push the current branch to each app's git remote
# using the service key. The cargo-chef Dockerfiles keep the rocksdb/dep compile
# cached, and the mingo app copies the SPA in its final layer, so SPA-only
# changes deploy in seconds.

KEY ?= $(HOME)/.ssh/donotuse_id_ed25519_service
HOST ?= dokku@sandmill.org
BRANCH ?= main
GIT_SSH = GIT_SSH_COMMAND="ssh -i $(KEY)"

.PHONY: deploy-daemon deploy-mingo deploy build

## Build the two deployed binaries locally (validates before pushing).
build:
	CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release -p sbo-daemon -p mingo-idp

## Deploy da.sandmill.org (sbo-daemon) via GitHub Actions: CI builds the image
## (persistent cache, ample disk) and dokku pulls it — the 24G host never
## compiles. Requires the DOKKU_SSH_KEY repo secret (see .github/workflows/
## deploy-daemon.yml). A push to main touching deploy/sbo-daemon/** also triggers
## it automatically. Legacy host build: `make deploy-daemon-onhost` (slow).
deploy-daemon:
	gh workflow run deploy-daemon.yml

## Legacy: build sbo-daemon ON the dokku host (slow; cold-compiles on a 24G disk).
deploy-daemon-onhost:
	$(GIT_SSH) git push $(HOST):sbo-daemon $(BRANCH):master

## Deploy mingo.place (mingo-idp + SPA).
deploy-mingo:
	$(GIT_SSH) git push $(HOST):mingo $(BRANCH):master

## Deploy both, concurrently. The two apps are independent dokku remotes with
## separate build caches, so there's no reason to serialize them — running in
## parallel roughly halves wall-clock when both rebuild. (Push progress from the
## two streams interleaves; the per-app "Application deployed" lines are final.)
deploy:
	$(MAKE) -j2 deploy-daemon deploy-mingo
