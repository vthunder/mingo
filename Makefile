# Mingo reference implementation — standard targets (same vocabulary in
# browserid-ng, sbo, browserid-bsky):
#
#   make build            compile the deployed binaries locally
#   make test             run the workspace test suite
#   make push             push HEAD to origin (triggers the CI image builds)
#   make watch            watch CI runs for HEAD until they all finish
#   make release          re-release HEAD's images to dokku (manual fallback)
#   make deploy           push + watch (CI itself releases — see below)
#
# Deploy model: BOTH prod apps (mingo → mingo.place, sbo-daemon →
# da.sandmill.org) build in CI (.github/workflows/deploy-*.yml) with a
# persistent type=gha layer cache and deploy by IMAGE (`dokku git:from-image`)
# — the 24G sandmill.org host never compiles. Unlike browserid-ng, this repo's
# DOKKU_SSH_KEY secret works, so CI does the release itself; `release` exists
# as a manual fallback for re-releasing a built image.

KEY  ?= $(HOME)/.ssh/mini-ops
HOST ?= dokku@sandmill.org
BRANCH ?= main
GIT_SSH = GIT_SSH_COMMAND="ssh -i $(KEY)"
SSH  := ssh -i $(KEY) -o StrictHostKeyChecking=accept-new
SHA  := $(shell git rev-parse HEAD)
REG  := ghcr.io/vthunder

.PHONY: build test push watch release release-mingo release-daemon deploy \
        deploy-daemon deploy-mingo deploy-mingo-onhost deploy-daemon-onhost

## Build the two deployed binaries locally (validates before pushing).
build:
	CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release -p sbo-daemon -p mingo-idp

test:
	cargo test --workspace

push:
	git push origin HEAD

# gh's --commit filter needs the FULL sha — a short sha silently matches nothing.
watch:
	@echo "Watching CI for $(SHA)…"
	@# Runs take a few seconds to register after a push — wait for them to
	@# APPEAR before waiting for them to finish, or this exits instantly.
	@until gh run list --commit $(SHA) --json status -q '.[].status' | grep -q .; do sleep 5; done
	@while gh run list --commit $(SHA) --json status -q '.[].status' \
	    | grep -qE 'in_progress|queued|requested|waiting'; do sleep 15; done
	@gh run list --commit $(SHA)

# Manual fallback releases (CI normally does this itself). `git:from-image`
# exits 1 on an unchanged digest — tolerated.
release-mingo:  ; -$(SSH) $(HOST) git:from-image mingo      $(REG)/mingo:$(SHA)
release-daemon: ; -$(SSH) $(HOST) git:from-image sbo-daemon $(REG)/sbo-daemon:$(SHA)
release: release-mingo release-daemon

deploy: push watch

## Trigger the per-app CI workflows without a triggering push.
deploy-daemon:
	gh workflow run deploy-daemon.yml
deploy-mingo:
	gh workflow run deploy-mingo.yml

## Legacy on-host builds (slow: the 24G host cold-compiles). NOTE: image
## deploys cleared the app's custom dockerfile-path, so before an on-host push
## you must restore it — and clear it again afterwards or the next
## git:from-image fails with `Invalid dockerfile-path`:
##   dokku builder-dockerfile:set mingo dockerfile-path deploy/mingo/Dockerfile
##   … push …
##   dokku builder-dockerfile:set mingo dockerfile-path
deploy-mingo-onhost:
	$(GIT_SSH) git push $(HOST):mingo $(BRANCH):main
deploy-daemon-onhost:
	$(GIT_SSH) git push $(HOST):sbo-daemon $(BRANCH):master
