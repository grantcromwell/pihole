#!/bin/sh
set -e
cd "$(dirname "$0")/.."
mkdir -p data
get()
{
    echo "Getting $2"
    curl -fsSL --retry 3 -o "data/$2.tmp" "$1"
    mv "data/$2.tmp" "data/$2"
}
get https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest arin
get https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest ripe
get https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest apnic
get https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest lacnic
get https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest afrinic
get https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts hosts
for asn in $(awk '/^allow_asns:/{on=1; next} /^[^ #-]/{on=0} on && /^ *-/{gsub(/[^0-9]/, "", $2); print $2}' policy/policy.yaml)
do
    echo "Getting networks for AS$asn"
    curl -fsSL --retry 3 "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS$asn" \
        | grep -oE '"prefix": ?"[0-9.]+/[0-9]+"' | grep -oE '[0-9.]+/[0-9]+' | sort -u > "data/as$asn.tmp"
    mv "data/as$asn.tmp" "data/as$asn"
done
echo "All lists are in router/data"
