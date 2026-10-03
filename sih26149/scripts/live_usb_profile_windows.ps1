$ErrorActionPreference = "Stop"

$usbDisks = Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' }

$results = @()

foreach ($disk in $usbDisks) {
    $size = $null
    if ($disk.Size -ne $null) {
        $bytes = [uint64]$disk.Size
        if ($bytes -ge 1TB) { $size = ("{0:N2} TB" -f ($bytes / 1TB)) }
        elseif ($bytes -ge 1GB) { $size = ("{0:N2} GB" -f ($bytes / 1GB)) }
        elseif ($bytes -ge 1MB) { $size = ("{0:N2} MB" -f ($bytes / 1MB)) }
        else { $size = ("{0} bytes" -f $bytes) }
    }

    $capability = [ordered]@{
        media_type = "USB_FLASH"
        recommended_level = "DESTROY"
        nist_reference = "NIST SP 800-88 Rev. 2 §2.5 Destroy"
        ieee_2883_reference = "IEEE 2883-2022 §5.5 — Removable flash storage: physical disintegration required when controller-level sanitize is unavailable or unverifiable. Consumer USB flash controllers provide no standardized purge command."
        clear_supported = $false
        purge_supported = $false
        purge_command = $null
        destroy_recommendation = "DISINTEGRATE"
        scope_statement = ("Live USB enumeration via Win32_DiskDrive on Windows host. DeviceID={0}; InterfaceType=USB; Media pre-classified as USB_FLASH per IEEE 2883-2022. Software CLEAR/PURGE not claimed — controller-level wear leveling, spare-area blocks, and bad-block remapping are vendor-proprietary and inaccessible from user space. NIST DESTROY (physical disintegration to ≤2mm particles) is the conservative default." -f $disk.DeviceID)
        classification_basis = @(
            "Win32_DiskDrive.InterfaceType == 'USB'",
            ("Win32_DiskDrive.MediaType = '{0}'" -f $disk.MediaType),
            "Detected as removable flash storage class per IEEE 2883-2022 §5.5"
        )
        warnings = @(
            "No hdparm/ATA passthrough available on Windows for HPA/DCO probing.",
            "Vendor-specific flash translation layer (FTL) may retain data in over-provisioned area.",
            "Chip-on-board (COB) monolithic devices may resist standard cross-cut shredding."
        )
        hpa_dco_warning = "HPA/DCO probing requires Linux + root + hdparm on raw block device. On Windows this is not available via user-space WMI."
        hpa_checked = $false
        hpa_detected = $null
        dco_checked = $false
        dco_detected = $null
        write_protection_note = "Write-blocker status not verified via WMI alone. Hardware write-blocker recommended before acquisition."
        is_sed_opal_capable = $false
        opal_ssc_version = $null
        crypto_erase_recommended = $false
        crypto_erase_rationale = "Consumer USB flash controllers do not implement TCG Opal or standardized cryptographic erase."
    }

    $entry = [ordered]@{
        device_id = $disk.DeviceID
        vendor = $disk.Manufacturer
        model = $disk.Model
        serial = $disk.SerialNumber
        media_type_pre_classified = "USB_FLASH"
        capacity_raw_bytes = $disk.Size
        capacity = $size
        interface_type = $disk.InterfaceType
        os_source = "Win32_DiskDrive (CIM/WMI)"
        device_capability = $capability
    }

    $results += $entry
}

$wrapper = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    os_family = "Windows"
    enumeration_source = "Get-CimInstance Win32_DiskDrive"
    usb_disk_count = $results.Count
    devices = $results
}

$wrapper | ConvertTo-Json -Depth 10
