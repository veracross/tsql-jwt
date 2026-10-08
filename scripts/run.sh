#!/usr/bin/env bash
#
# Helper for running the tsql-jwt functions against SQL Server 2025 in docker.
#
#   scripts/run.sh up                      start the container and wait until healthy
#   scripts/run.sh down                    stop and remove the container
#   scripts/run.sh deploy [sql_dir]        (re)create the database and deploy sql_dir (default: sql/)
#   scripts/run.sh test                    deploy sql/ and run tests/*.sql
#   scripts/run.sh bench [git_ref] [label] deploy sql/ from git_ref (default: working tree) and run bench/bench.sql
#   scripts/run.sh sql "select 1"          run an ad-hoc query against the test database
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINER="tsql-jwt-mssql"
DB="${MSSQL_DB:-tsql_jwt}"
SA_PASSWORD="${MSSQL_SA_PASSWORD:-TsqlJwt!Passw0rd}"
SQLCMD=/opt/mssql-tools18/bin/sqlcmd

# sqlcmd [db] [extra args...] < script
sqlcmd() {
    local db="$1"; shift
    docker exec -i "$CONTAINER" "$SQLCMD" -C -S localhost -U sa -P "$SA_PASSWORD" -d "$db" -I "$@" -i /dev/stdin
}

up() {
    docker compose -f "$ROOT/docker-compose.yml" up -d --wait
}

down() {
    docker compose -f "$ROOT/docker-compose.yml" down
}

deploy() {
    local dir="${1:-$ROOT/sql}"
    sqlcmd master -b <<SQL
if db_id('$DB') is not null
begin
    alter database [$DB] set single_user with rollback immediate
    drop database [$DB]
end
create database [$DB]
SQL
    for f in "$dir"/*.sql; do
        sqlcmd "$DB" -b -h -1 < "$f" > /dev/null
    done
    echo "deployed $(ls "$dir"/*.sql | wc -l | tr -d ' ') files from $dir to $DB"
}

run_tests() {
    deploy "$ROOT/sql"
    sqlcmd "$DB" -b < "$ROOT/tests/_framework.sql"

    # Test files run with nocount on, so any output means a batch raised an error
    local errors=0 out
    for f in "$ROOT"/tests/test_*.sql; do
        out="$({ echo "set nocount on"; cat "$f"; } | sqlcmd "$DB")"
        if [[ -n "$out" ]]; then
            echo "ERROR in $(basename "$f"):"
            echo "$out"
            errors=1
        fi
    done

    sqlcmd "$DB" -b -W -s ' | ' < "$ROOT/tests/_report.sql" && (( errors == 0 ))
}

bench() {
    local ref="${1:-}"
    local label="${2:-${ref:-working-tree}}"
    local dir="$ROOT/sql"
    if [[ -n "$ref" ]]; then
        dir="$(mktemp -d)"
        trap 'rm -rf "$dir"' RETURN
        git -C "$ROOT" archive "$ref" sql | tar -x -C "$dir"
        dir="$dir/sql"
    fi
    deploy "$dir"
    local out
    out="$(sed "s/\$(label)/$label/g" "$ROOT/bench/bench.sql" | sqlcmd "$DB" -b -h -1 -W -s ',')"
    echo "$out"
    local results="$ROOT/bench/results.csv"
    [[ -f "$results" ]] || echo "label,case,calls,median_ms,us_per_call" > "$results"
    echo "$out" | grep '^bench,' | sed 's/^bench,//' >> "$results"
}

cmd="${1:-}"; shift || true
case "$cmd" in
    up)     up ;;
    down)   down ;;
    deploy) deploy "$@" ;;
    test)   run_tests ;;
    bench)  bench "$@" ;;
    sql)    echo "$1" | sqlcmd "$DB" -W ;;
    *)      sed -n '3,11p' "$0"; exit 1 ;;
esac
