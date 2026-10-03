#!/usr/bin/env bash
set -euo pipefail

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%S%z)"

DEVICE_IDS=""
if command -v lsblk >/dev/null 2>&1; then
    DEVICE_IDS="$(lsblk -d -n -o NAME,TYPE 2>/dev/null | awk '$2=="disk" {print $1}')"
fi

JSON_DEVICES=""
DEV_COUNT=0

for dev in $DEVICE_IDS; do
    SYS_PATH="/sys/block/$dev"
    [ -d "$SYS_PATH" ] || continue

    REMOVABLE=""
    [ -f "$SYS_PATH/removable" ] && REMOVABLE="$(cat "$SYS_PATH/removable" 2>/dev/null || true)"

    IS_USB=0
    VENDOR=""
    if [ -f "$SYS_PATH/device/vendor" ]; then
        VENDOR="$(cat "$SYS_PATH/device/vendor" 2>/dev/null || true)"
    fi

    DEVPATH=""
    if command -v udevadm >/dev/null 2>&1; then
        DEVPATH="$(udevadm info --query=property --name="/dev/$dev" 2>/dev/null | awk -F= '/^ID_BUS=/ {print $2; exit}' || true)"
    fi

    if [ "$REMOVABLE" = "1" ] || echo "$DEVPATH" | grep -qi "usb"; then
        IS_USB=1
    fi

    if [ "$IS_USB" -ne 1 ]; then
        continue
    fi

    SERIAL=""
    MODEL=""
    if command -v udevadm >/dev/null 2>&1; then
        SERIAL="$(udevadm info --query=property --name="/dev/$dev" 2>/dev/null | awk -F= '/^ID_SERIAL=/ {print $2; exit}' || true)"
        MODEL="$(udevadm info --query=property --name="/dev/$dev" 2>/dev/null | awk -F= '/^ID_MODEL=/ {gsub(/_/," "); print $2; exit}' || true)"
    fi

    if [ -z "$VENDOR" ] && command -v lsblk >/dev/null 2>&1; then
        VENDOR="$(lsblk -d -n -o VENDOR "/dev/$dev" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)"
    fi
    if [ -z "$MODEL" ] && command -v lsblk >/dev/null 2>&1; then
        MODEL="$(lsblk -d -n -o MODEL "/dev/$dev" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)"
    fi
    if [ -z "$SERIAL" ] && command -v lsblk >/dev/null 2>&1; then
        SERIAL="$(lsblk -d -n -o SERIAL "/dev/$dev" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)"
    fi

    SIZE_BYTES=""
    if [ -f "$SYS_PATH/size" ]; then
        SECTORS="$(cat "$SYS_PATH/size" 2>/dev/null || true)"
        if [ -n "$SECTORS" ]; then
            SIZE_BYTES=$(( SECTORS * 512 ))
        fi
    fi
    if [ -z "$SIZE_BYTES" ] && command -v lsblk >/dev/null 2>&1; then
        SIZE_BYTES="$(lsblk -d -n -b -o SIZE "/dev/$dev" 2>/dev/null | tr -d ' ' || true)"
    fi

    SIZE=""
    if [ -n "$SIZE_BYTES" ]; then
        if [ "$SIZE_BYTES" -ge 1099511627776 ]; then
            SIZE="$(awk -v b="$SIZE_BYTES" 'BEGIN{printf "%.2f TB", b/1099511627776}')"
        elif [ "$SIZE_BYTES" -ge 1073741824 ]; then
            SIZE="$(awk -v b="$SIZE_BYTES" 'BEGIN{printf "%.2f GB", b/1073741824}')"
        elif [ "$SIZE_BYTES" -ge 1048576 ]; then
            SIZE="$(awk -v b="$SIZE_BYTES" 'BEGIN{printf "%.2f MB", b/1048576}')"
        else
            SIZE="${SIZE_BYTES} bytes"
        fi
    fi

    DEV_COUNT=$((DEV_COUNT + 1))

    ESCAPED_VENDOR="$(printf '%s' "$VENDOR" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || printf '"%s"' "$VENDOR")"
    ESCAPED_MODEL="$(printf '%s' "$MODEL" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || printf '"%s"' "$MODEL")"
    ESCAPED_SERIAL="$(printf '%s' "$SERIAL" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || printf '"%s"' "$SERIAL")"
    ESCAPED_DEVID="$(printf '%s' "/dev/$dev" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || printf '"/dev/%s"' "$dev")"
    ESCAPED_CAPACITY="$(printf '%s' "$SIZE" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || printf '"%s"' "$SIZE")"

    DEV_JSON=$(cat <<DEVEOF
    {
      "device_id": $ESCAPED_DEVID,
      "vendor": $ESCAPED_VENDOR,
      "model": $ESCAPED_MODEL,
      "serial": $ESCAPED_SERIAL,
      "media_type_pre_classified": "USB_FLASH",
      "capacity_raw_bytes": ${SIZE_BYTES:-null},
      "capacity": $ESCAPED_CAPACITY,
      "interface_type": "USB",
      "os_source": "sysfs + udevadm + lsblk",
      "device_capability": {
        "media_type": "USB_FLASH",
        "recommended_level": "DESTROY",
        "nist_reference": "NIST SP 800-88 Rev. 2 §2.5 Destroy",
        "ieee_2883_reference": "IEEE 2883-2022 §5.5 — Removable flash storage: physical disintegration required when controller-level sanitize is unavailable or unverifiable. Consumer USB flash controllers provide no standardized purge command.",
        "clear_supported": false,
        "purge_supported": false,
        "purge_command": null,
        "destroy_recommendation": "DISINTEGRATE",
        "scope_statement": "Live block-device enumeration on Linux host. Classified USB_FLASH based on sysfs removable flag + udevadm ID_BUS + IEEE 2883-2022 §5.5. Software CLEAR/PURGE not claimed — flash translation layer spare-area blocks and wear-remapped pages are not user-addressable. Run hdparm -N and hdparm --dco-identify as root separately for HPA/DCO.",
        "classification_basis": [
          "/sys/block/$dev/removable == $REMOVABLE",
          "udevadm ID_BUS == ${DEVPATH:-<n/a>}",
          "Detected as removable flash storage class per IEEE 2883-2022 §5.5"
        ],
        "warnings": [
          "Run hdparm(8) as root to probe HPA and DCO explicitly; results not included here to avoid non-zero exit on uninitialized systems.",
          "Vendor-specific flash translation layer (FTL) may retain data in over-provisioned area.",
          "Chip-on-board (COB) monolithic devices may resist standard cross-cut shredding."
        ],
        "hpa_dco_warning": "HPA/DCO probe requires root privileges; this script runs user-space enumeration only. Execute `hdparm -N /dev/$dev` and `hdparm --dco-identify /dev/$dev` as root.",
        "hpa_checked": false,
        "hpa_detected": null,
        "dco_checked": false,
        "dco_detected": null,
        "write_protection_note": "Write-blocker status not asserted here. Recommend hardware write-blocker or `blockdev --setro` before forensic acquisition.",
        "is_sed_opal_capable": false,
        "opal_ssc_version": null,
        "crypto_erase_recommended": false,
        "crypto_erase_rationale": "Consumer USB flash controllers do not implement TCG Opal or standardized cryptographic erase."
      }
    }
DEVEOF
)

    if [ -n "$JSON_DEVICES" ]; then
        JSON_DEVICES="${JSON_DEVICES},
"
    fi
    JSON_DEVICES="${JSON_DEVICES}${DEV_JSON}"
done

cat <<EOF
{
  "generated_at": "$GENERATED_AT",
  "os_family": "Linux",
  "enumeration_source": "sysfs(/sys/block) + udevadm + lsblk",
  "usb_disk_count": $DEV_COUNT,
  "devices": [
$JSON_DEVICES
  ]
}
EOF
