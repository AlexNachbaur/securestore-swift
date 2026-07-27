#!/usr/bin/env bash
#
# Runs the test suite against a real Secret Service, so LinuxSecureStore is exercised rather
# than merely compiled. Must be invoked under `dbus-run-session`, which supplies the session
# bus gnome-keyring is reached over.
#
# Standing one up headless has one genuinely non-obvious requirement, and it cost several CI
# rounds to find:
#
#   `gnome-keyring-daemon --daemonize` RETURNS BEFORE IT HAS CLAIMED org.freedesktop.secrets.
#
# Measured in this container: NameHasOwner is false the instant the call returns and true about
# a second later, on every run. Anything that touches the Secret Service inside that window
# never reaches this daemon — D-Bus instead *activates* a second gnome-keyring-daemon, which
# never received the password, cannot read the keyring the first one wrote ("keyring was in an
# invalid or unrecognized format"), and falls back to a prompter that cannot run headless.
#
# It is a race a developer machine wins and a CI runner loses, which is why several
# plausible-looking fixes appeared to work locally. Hence wait_for_secret_service below: it is
# load-bearing, not defensive.
#
# The password is empty and newline-terminated — empty so the keyring auto-unlocks for whichever
# daemon serves the bus, newline-terminated or the daemon never creates one at all.

set -uo pipefail

readonly SERVICE_NAME=org.freedesktop.secrets
readonly PROBE_SCHEMA=securestore-ci

# Blocks until the daemon owns the bus name, or gives up after ~30s.
wait_for_secret_service() {
    local owned=""
    for _ in $(seq 1 60); do
        owned=$(
            dbus-send --session --dest=org.freedesktop.DBus --print-reply \
                /org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner \
                "string:${SERVICE_NAME}" 2>/dev/null | tail -1 | grep -o 'true'
        )
        [ "$owned" = "true" ] && return 0
        sleep 0.5
    done
    return 1
}

# Proves the environment before the suite can blame the code. secret-tool is libsecret's own
# client, so a failure here means the container is misconfigured and LinuxSecureStore has not
# been reached — worth knowing before reading a screen of identical test failures.
probe_secret_service() {
    echo probe | secret-tool store --label=probe "$PROBE_SCHEMA" probe || return 1
    secret-tool clear "$PROBE_SCHEMA" probe
}

main() {
    eval "$(printf '\n' | gnome-keyring-daemon --daemonize --unlock --components=secrets)"

    if ! wait_for_secret_service; then
        echo "::error::gnome-keyring never claimed ${SERVICE_NAME}"
        exit 1
    fi

    if ! probe_secret_service; then
        echo "::error::No usable Secret Service. Keyring directory contains:"
        ls -la "${XDG_DATA_HOME:-$HOME/.local/share}/keyrings" || echo "  (no keyrings directory)"
        exit 1
    fi
    echo "Secret Service is reachable and writable."

    set -e
    swift test
}

main "$@"
