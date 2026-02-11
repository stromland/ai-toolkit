#!/usr/bin/env bash

DEPENDENCIES=(curl jq)
SCRIPT_NAME=$(basename "$0")
SCRIPT_VERSION="1.0.0"
CURL_OPTS=(-s --max-time 10 -f)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [[ -n "${NO_COLOR:-}" ]] || [[ "${TERM:-}" == "dumb" ]]; then
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    NC=""
fi

warnings=()
criticals=()

function usage() {
    cat <<EOM

Review npm packages for security, maintenance, and trust signals.

usage: ${SCRIPT_NAME} [options] [package-name] [version]

options:
    -p|--package      <name>     Package name to review (alternative to positional arg)
    -v|--pkg-version  <version>  Package version to check (default: latest)
    -h|--help                    Show this help message
    --version                    Show version information

dependencies: ${DEPENDENCIES[@]}

examples:
    ${SCRIPT_NAME} express
    ${SCRIPT_NAME} express 4.21.0
    ${SCRIPT_NAME} -p @babel/core -v 7.24.0
    ${SCRIPT_NAME} @types/node

EOM
    exit 1
}

function main() {
    local package=""
    local pkg_version=""

    while [ "$1" != "" ]; do
        case $1 in
        -p | --package)
            shift
            package="$1"
            ;;
        -v | --pkg-version)
            shift
            pkg_version="$1"
            ;;
        --version)
            echo "${SCRIPT_NAME} version ${SCRIPT_VERSION}"
            exit 0
            ;;
        -h | --help)
            usage
            ;;
        -*)
            print_error "Unknown option '$1'"
            usage
            ;;
        *)
            if [ -z "$package" ]; then
                package="$1"
            elif [ -z "$pkg_version" ]; then
                pkg_version="$1"
            else
                print_error "Unexpected argument '$1'"
                usage
            fi
            ;;
        esac
        shift
    done

    if [ -z "$package" ]; then
        print_error "Package name is required"
        usage
    fi

    exit_on_missing_tools "${DEPENDENCIES[@]}"

    review_package "$package" "$pkg_version"
}

function review_package() {
    local package="$1"
    local pkg_version="$2"
    local encoded_package
    encoded_package=$(url_encode "$package")

    warnings=()
    criticals=()

    echo "=== npm Package Review: $package ==="
    echo ""

    echo "--- npm Registry ---"
    local npm_data
    npm_data=$(curl "${CURL_OPTS[@]}" "https://registry.npmjs.org/${encoded_package}" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "RESULT: STOP"
        echo "REASON: Package '$package' not found on npm registry"
        return 0
    fi

    if [ -z "$pkg_version" ]; then
        pkg_version=$(echo "$npm_data" | jq -r '.["dist-tags"].latest // empty')
        if [ -z "$pkg_version" ]; then
            echo "RESULT: STOP"
            echo "REASON: Could not determine latest version"
            return 0
        fi
    fi
    echo "Version: $pkg_version"

    check_maintainers "$npm_data"
    check_repository "$npm_data"
    check_license "$npm_data"

    local version_data
    version_data=$(echo "$npm_data" | jq --arg v "$pkg_version" '.versions[$v] // empty')
    local time_data
    time_data=$(echo "$npm_data" | jq '.time // {}')

    check_publish_dates "$time_data" "$pkg_version"
    check_install_scripts "$version_data" "$pkg_version"
    check_dependency_count "$version_data"

    echo ""

    check_downloads "$encoded_package"

    echo ""

    check_deps_dev "$encoded_package" "$pkg_version"

    echo ""

    print_summary
}

function check_maintainers() {
    local npm_data="$1"
    local maintainer_count
    local maintainer_names

    maintainer_count=$(echo "$npm_data" | jq '[.maintainers // [] | length] | .[0]')
    maintainer_names=$(echo "$npm_data" | jq -r '[.maintainers[]?.name] | join(", ")')
    echo "Maintainers ($maintainer_count): $maintainer_names"

    if [ "$maintainer_count" -eq 0 ]; then
        criticals+=("No maintainers listed")
    elif [ "$maintainer_count" -eq 1 ]; then
        warnings+=("Single maintainer: $maintainer_names")
    fi
}

function check_repository() {
    local npm_data="$1"
    local repo_url
    repo_url=$(echo "$npm_data" | jq -r '
      if .repository then
        if (.repository | type) == "string" then .repository
        elif .repository.url then .repository.url
        else "none"
        end
      else "none"
      end
    ')
    local repo_display="$repo_url"
    repo_display="${repo_display#git+}"
    repo_display="${repo_display%.git}"
    echo "Repository: $repo_display"

    if [ "$repo_url" = "none" ] || [ "$repo_url" = "null" ] || [ -z "$repo_url" ]; then
        warnings+=("No repository URL — cannot verify source code")
    fi
}

function check_license() {
    local npm_data="$1"
    local license
    license=$(echo "$npm_data" | jq -r '.license // "unknown"')
    echo "License: $license"

    local known_licenses="MIT ISC BSD-2-Clause BSD-3-Clause Apache-2.0 0BSD Unlicense CC0-1.0 BlueOak-1.0.0"
    if [ "$license" = "unknown" ] || [ "$license" = "null" ] || [ -z "$license" ]; then
        warnings+=("No license specified")
    elif ! echo "$known_licenses" | grep -qw "$license"; then
        warnings+=("Unusual license: $license — review before use")
    fi
}

function check_publish_dates() {
    local time_data="$1"
    local pkg_version="$2"
    local latest_publish
    local created
    local now_epoch

    latest_publish=$(echo "$time_data" | jq -r --arg v "$pkg_version" '.[$v] // empty')
    created=$(echo "$time_data" | jq -r '.created // empty')
    now_epoch=$(date +%s)

    if [ -n "$latest_publish" ]; then
        echo "Published: $latest_publish"
        local publish_epoch
        publish_epoch=$(date -d "$latest_publish" +%s 2>/dev/null || echo "0")
        local two_years=$((730 * 86400))
        if [ "$publish_epoch" -gt 0 ] && [ $((now_epoch - publish_epoch)) -gt $two_years ]; then
            warnings+=("Last published over 2 years ago — possibly unmaintained")
        fi
    fi

    if [ -n "$created" ]; then
        echo "Created: $created"
        local created_epoch
        created_epoch=$(date -d "$created" +%s 2>/dev/null || echo "0")
        local thirty_days=$((30 * 86400))
        if [ "$created_epoch" -gt 0 ] && [ $((now_epoch - created_epoch)) -lt $thirty_days ]; then
            warnings+=("Package is very new (created < 30 days ago)")
        fi
    fi
}

function check_install_scripts() {
    local version_data="$1"
    local pkg_version="$2"

    if [ -n "$version_data" ]; then
        local install_scripts
        install_scripts=$(echo "$version_data" | jq -r '[
          .scripts // {} |
          to_entries[] |
          select(.key | test("^(preinstall|postinstall|install|preuninstall|postuninstall)$")) |
          "\(.key): \(.value)"
        ] | join("\n")')
        if [ -n "$install_scripts" ]; then
            echo "⚠ Install scripts detected:"
            echo "$install_scripts" | sed 's/^/  /'
            criticals+=("Has install scripts (preinstall/postinstall) — review carefully for malicious behavior")
        else
            echo "Install scripts: none"
        fi
    else
        echo "Install scripts: could not check (version data unavailable)"
        warnings+=("Could not verify install scripts for version $pkg_version")
    fi
}

function check_dependency_count() {
    local version_data="$1"

    if [ -n "$version_data" ]; then
        local dep_count
        dep_count=$(echo "$version_data" | jq '[.dependencies // {} | length] | .[0]')
        echo "Dependencies: $dep_count"
        if [ "$dep_count" -gt 50 ]; then
            warnings+=("High dependency count: $dep_count (larger attack surface)")
        fi
    fi
}

function check_downloads() {
    local encoded_package="$1"

    echo "--- Downloads ---"
    local downloads_data
    downloads_data=$(curl "${CURL_OPTS[@]}" "https://api.npmjs.org/downloads/point/last-week/${encoded_package}" 2>/dev/null) || true

    if [ -n "$downloads_data" ]; then
        local weekly_downloads
        weekly_downloads=$(echo "$downloads_data" | jq -r '.downloads // 0')
        echo "Weekly downloads: $weekly_downloads"
        if [ "$weekly_downloads" -lt 100 ]; then
            criticals+=("Extremely low downloads ($weekly_downloads/week) — high typosquat/malware risk")
        elif [ "$weekly_downloads" -lt 1000 ]; then
            warnings+=("Low downloads ($weekly_downloads/week) — possible typosquat risk")
        fi
    else
        echo "Weekly downloads: unavailable"
        warnings+=("Could not fetch download statistics")
    fi
}

function check_deps_dev() {
    local encoded_package="$1"
    local pkg_version="$2"

    echo "--- deps.dev (Google Open Source Insights) ---"
    local deps_data
    deps_data=$(curl "${CURL_OPTS[@]}" "https://api.deps.dev/v3/systems/npm/packages/${encoded_package}/versions/${pkg_version}" 2>/dev/null) || true

    if [ -n "$deps_data" ] && echo "$deps_data" | jq empty 2>/dev/null; then
        local advisory_count
        advisory_count=$(echo "$deps_data" | jq '[.advisoryKeys // [] | length] | .[0]')
        if [ "$advisory_count" -gt 0 ]; then
            echo "⚠ Known vulnerabilities: $advisory_count"
            echo "$deps_data" | jq -r '.advisoryKeys[]?.id // empty' | while read -r adv_id; do
                echo "  - $adv_id (https://deps.dev/advisory/$adv_id)"
            done
            criticals+=("$advisory_count known vulnerability/vulnerabilities — see advisory links above")
        else
            echo "Known vulnerabilities: 0"
        fi

        local deps_links
        deps_links=$(echo "$deps_data" | jq -r '[.links[]? | "\(.label): \(.url)"] | join("\n")')
        if [ -n "$deps_links" ]; then
            echo "Links:"
            echo "$deps_links" | sed 's/^/  /'
        fi
    else
        echo "deps.dev data: unavailable (package may not be indexed yet)"
        warnings+=("Could not fetch deps.dev data — no vulnerability check performed")
    fi

    check_scorecard "$deps_data"
}

function check_scorecard() {
    local deps_data="$1"

    echo ""
    echo "--- OpenSSF Scorecard ---"
    local scorecard_done=false

    if [ -n "$deps_data" ] && echo "$deps_data" | jq empty 2>/dev/null; then
        local project_id
        project_id=$(echo "$deps_data" | jq -r '[.relatedProjects[]? | select(.relationType == "SOURCE_REPO") | .projectKey.id] | first // empty')

        if [ -n "$project_id" ]; then
            local encoded_project_id
            encoded_project_id="${project_id//\//%2F}"
            local scorecard_data
            scorecard_data=$(curl "${CURL_OPTS[@]}" "https://api.deps.dev/v3/projects/${encoded_project_id}" 2>/dev/null) || true

            if [ -n "$scorecard_data" ] && echo "$scorecard_data" | jq -e '.scorecard.checks' &>/dev/null; then
                local score
                score=$(echo "$scorecard_data" | jq '[.scorecard.checks[] | select(.score >= 0) | .score] | add / length | . * 10 | round / 10')
                echo "Average score: $score / 10"
                echo "$scorecard_data" | jq -r '.scorecard.checks[] | select(.score >= 0) | "  \(.name): \(.score)/10"' 2>/dev/null || true
                local score_int="${score%.*}"
                if [ -n "$score_int" ] && [ "$score_int" -lt 4 ] 2>/dev/null; then
                    warnings+=("Low OpenSSF Scorecard score: $score/10")
                fi
                scorecard_done=true
            fi
        fi
    fi

    if [ "$scorecard_done" = false ]; then
        echo "Scorecard: not available"
    fi
}

function print_summary() {
    echo "=============================="
    echo "=== SUMMARY ==="
    echo "=============================="
    echo ""

    if [ ${#criticals[@]} -gt 0 ]; then
        echo "🔴 CRITICAL ISSUES:"
        for c in "${criticals[@]}"; do
            echo "  - $c"
        done
        echo ""
    fi

    if [ ${#warnings[@]} -gt 0 ]; then
        echo "🟡 WARNINGS:"
        for w in "${warnings[@]}"; do
            echo "  - $w"
        done
        echo ""
    fi

    if [ ${#criticals[@]} -gt 0 ]; then
        echo "RECOMMENDATION: 🔴 STOP"
        echo "This package has critical security concerns. Do NOT install without explicit user approval."
    elif [ ${#warnings[@]} -gt 3 ]; then
        echo "RECOMMENDATION: 🟡 CAUTION"
        echo "Multiple warnings detected. Inform the user and get confirmation before installing."
    elif [ ${#warnings[@]} -gt 0 ]; then
        echo "RECOMMENDATION: 🟡 CAUTION"
        echo "Minor concerns detected. Inform the user of the warnings."
    else
        echo "RECOMMENDATION: 🟢 GO"
        echo "No issues detected. Safe to install."
    fi
}

function exit_on_missing_tools() {
    for cmd in "$@"; do
        if command -v "$cmd" &>/dev/null; then
            continue
        fi
        printf "Error: Required tool '%s' is not installed or not in PATH\n" "$cmd" >&2
        exit 1
    done
}

function url_encode() {
    local str="$1"
    str="${str//@/%40}"
    str="${str//\//%2F}"
    echo "$str"
}

function print_error() {
    echo -e "${RED}Error: $1${NC}" >&2
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
    exit 0
fi
