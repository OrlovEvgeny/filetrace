# shellcheck shell=sh
# Assertions for the scripts under cases/, which run as root in a container
# with the packages at /pkg/old and /pkg/new and FT_VERSION set to the version
# the new binaries report.

checks=0
failures=0

fail()
{
    printf 'FAIL %s\n' "$*" >&2
    failures=$((failures + 1))
}

# expect_exit <codes separated by "|"> <command...>
expect_exit()
{
    wanted=$1
    shift
    checks=$((checks + 1))
    code=0
    "$@" >/dev/null 2>&1 || code=$?
    case "|$wanted|" in
    *"|$code|"*) ;;
    *) fail "'$*' exited with $code, expected $wanted" ;;
    esac
}

# expect_eq <what> <expected> <actual>
expect_eq()
{
    checks=$((checks + 1))
    [ "$2" = "$3" ] || fail "$1 is '$3', expected '$2'"
}

expect_file()
{
    checks=$((checks + 1))
    [ -e "$1" ] || fail "$1 is missing"
}

expect_no_file()
{
    checks=$((checks + 1))
    [ ! -e "$1" ] || fail "$1 is still there"
}

# The agent has no readiness signal; 0 and 9 both mean it is collecting.
wait_running()
{
    tries=20
    while [ "$tries" -gt 0 ]; do
        code=0
        filetrace agent status >/dev/null 2>&1 || code=$?
        case $code in
        0 | 9) return 0 ;;
        esac
        sleep 1
        tries=$((tries - 1))
    done
    return 1
}

expect_running()
{
    checks=$((checks + 1))
    wait_running || fail "$1: the agent is not running"
}

expect_stopped()
{
    expect_exit 4 filetrace agent status
}

agent_pid()
{
    filetrace agent status 2>/dev/null | sed -n 's/^PID: *//p'
}

expect_version()
{
    expect_eq 'the command version' "Filetrace $FT_VERSION" "$(filetrace version | head -n 1)"
    expect_eq 'the agent version' "Filetrace agent $FT_VERSION" "$(filetrace-agent --version)"
}

summary()
{
    printf '%s: %d checks, %d failed\n' "$1" "$checks" "$failures"
    [ "$failures" -eq 0 ]
}
