const VENDOR_HINTS = [
  ['AMI', /^(ami|american\s+megatrends)\b/i],
  ['Award', /^award\b/i],
  ['Phoenix', /^phoenix\b/i],
  ['Dell', /^(dell|supportassist|diagnostic)\b/i],
  ['HP', /^(hp|hewlett[- ]packard)\b/i],
  ['Lenovo', /^lenovo\b/i],
  ['ASUS', /^asus\b/i],
  ['MSI', /^msi\b/i],
  ['Gigabyte', /^gigabyte\b/i]
];

const FAMILY_LABELS = {
  beep: 'Beep / speaker POST pattern',
  qcode: 'Two-character / Q-Code style display',
  hex: 'Hexadecimal POST / diagnostic code',
  decimal: 'Numeric POST / diagnostic code',
  branded: 'Vendor-branded diagnostic code',
  text: 'Textual BIOS/UEFI message',
  unknown: 'Unclassified diagnostic input'
};

const STATUS_LABELS = {
  error: 'Confirmed error',
  warning: 'Warning / diagnostic condition',
  stage: 'POST progress stage',
  success: 'Normal / success state',
  ambiguous: 'Vendor-dependent',
  unknown: 'Unknown'
};

const POST_CODES = {
AMI: {

    '01': {
      status: 'stage',
      meaning: 'Power on; reset type detection (soft/hard)',
      note: 'Normal early POST progress checkpoint.'
    },

    '02': {
      status: 'stage',
      meaning: 'AP initialization before microcode loading',
      note: 'Normal early CPU initialization stage.'
    },

    '03': {
      status: 'stage',
      meaning: 'North Bridge initialization before microcode loading',
      note: 'Normal early platform initialization stage.'
    },

    '04': {
      status: 'stage',
      meaning: 'South Bridge initialization before microcode loading',
      note: 'Normal early platform initialization stage.'
    },

    '06': {
      status: 'stage',
      meaning: 'Microcode loading',
      note: 'Normal processor initialization stage.'
    },

    '07': {
      status: 'stage',
      meaning: 'AP initialization after microcode loading',
      note: 'Normal POST progress checkpoint.'
    },

    '08': {
      status: 'stage',
      meaning: 'North Bridge initialization after microcode loading',
      note: 'Normal POST progress checkpoint.'
    },

    '09': {
      status: 'stage',
      meaning: 'South Bridge initialization after microcode loading',
      note: 'Normal POST progress checkpoint.'
    },

    '0A': {
      status: 'stage',
      meaning: 'Reserved / firmware-specific SEC progress code',
      note: 'Interpretation may depend on the firmware implementation.'
    },

    '0B': {
      status: 'stage',
      meaning: 'Cache initialization',
      note: 'Normal early POST progress checkpoint.'
    },

    '0E': {
      status: 'error',
      meaning: 'Microcode not found',
      note: 'Firmware could not find required processor microcode.'
    },

    '0F': {
      status: 'error',
      meaning: 'Microcode not loaded',
      note: 'Firmware failed to load processor microcode.'
    },

    '10': {
      status: 'stage',
      meaning: 'PEI Core started',
      note: 'Normal POST progress checkpoint.'
    },

    '11': {
      status: 'stage',
      meaning: 'Pre-memory CPU initialization started',
      note: 'Normal early CPU initialization.'
    },

    '12': {
      status: 'stage',
      meaning: 'Pre-memory CPU initialization; CPU-module-specific',
      note: 'Exact activity depends on the processor/firmware implementation.'
    },

    '13': {
      status: 'stage',
      meaning: 'Pre-memory CPU initialization; CPU-module-specific',
      note: 'Exact activity depends on the processor/firmware implementation.'
    },

    '14': {
      status: 'stage',
      meaning: 'Pre-memory CPU initialization; CPU-module-specific',
      note: 'Exact activity depends on the processor/firmware implementation.'
    },

    '15': {
      status: 'stage',
      meaning: 'Pre-memory North Bridge initialization started',
      note: 'Normal platform initialization stage.'
    },

    '16': {
      status: 'stage',
      meaning: 'Pre-memory North Bridge initialization; module-specific',
      note: 'Exact activity depends on the platform firmware.'
    },

    '17': {
      status: 'stage',
      meaning: 'Pre-memory North Bridge initialization; module-specific',
      note: 'Exact activity depends on the platform firmware.'
    },

    '18': {
      status: 'stage',
      meaning: 'Pre-memory North Bridge initialization; module-specific',
      note: 'Exact activity depends on the platform firmware.'
    },

    '19': {
      status: 'stage',
      meaning: 'Pre-memory South Bridge initialization started',
      note: 'Normal platform initialization stage.'
    },

    '1A': {
      status: 'stage',
      meaning: 'Pre-memory South Bridge initialization; module-specific',
      note: 'Exact activity depends on the platform firmware.'
    },

    '1B': {
      status: 'stage',
      meaning: 'Pre-memory South Bridge initialization; module-specific',
      note: 'Exact activity depends on the platform firmware.'
    },

    '1C': {
      status: 'stage',
      meaning: 'Pre-memory South Bridge initialization; module-specific',
      note: 'Exact activity depends on the platform firmware.'
    },

    '2B': {
      status: 'stage',
      meaning: 'Memory initialization; SPD data reading',
      note: 'Firmware is reading Serial Presence Detect information from memory.'
    },

    '2C': {
      status: 'stage',
      meaning: 'Memory initialization; memory presence detection',
      note: 'Firmware is detecting installed memory.'
    },

    '2D': {
      status: 'stage',
      meaning: 'Memory initialization; programming memory timing information',
      note: 'Normal memory-configuration stage.'
    },

    '2E': {
      status: 'stage',
      meaning: 'Memory initialization; configuring memory',
      note: 'Normal memory-configuration stage.'
    },

    '2F': {
      status: 'stage',
      meaning: 'Memory initialization; other',
      note: 'Firmware-specific memory initialization activity.'
    },

    '31': {
      status: 'stage',
      meaning: 'Memory installed',
      note: 'Normal POST checkpoint after memory detection.'
    },

    '32': {
      status: 'stage',
      meaning: 'CPU post-memory initialization started',
      note: 'Normal CPU initialization stage after memory is available.'
    },

    '33': {
      status: 'stage',
      meaning: 'CPU post-memory initialization; cache initialization',
      note: 'Normal POST progress checkpoint.'
    },

    '34': {
      status: 'stage',
      meaning: 'CPU post-memory initialization; application processor initialization',
      note: 'Normal multi-processor initialization stage.'
    },

    '35': {
      status: 'stage',
      meaning: 'CPU post-memory initialization; bootstrap processor selection',
      note: 'Normal POST progress checkpoint.'
    },

    '36': {
      status: 'stage',
      meaning: 'CPU post-memory initialization; SMM initialization',
      note: 'Normal firmware initialization stage.'
    },

    '37': {
      status: 'stage',
      meaning: 'Post-memory North Bridge initialization started',
      note: 'Normal platform initialization stage.'
    },

    '38': {
      status: 'stage',
      meaning: 'Post-memory North Bridge initialization; module-specific',
      note: 'Exact activity depends on the platform firmware.'
    },

    '39': {
      status: 'stage',
      meaning: 'Post-memory North Bridge initialization; module-specific',
      note: 'Exact activity depends on the platform firmware.'
    },

    '3A': {
      status: 'stage',
      meaning: 'Post-memory North Bridge initialization; module-specific',
      note: 'Exact activity depends on the platform firmware.'
    },

    '3B': {
      status: 'stage',
      meaning: 'Post-memory South Bridge initialization started',
      note: 'Normal platform initialization stage.'
    },

    '3C': {
      status: 'stage',
      meaning: 'Post-memory South Bridge initialization; module-specific',
      note: 'Exact activity depends on the platform firmware.'
    },

    '3D': {
      status: 'stage',
      meaning: 'Post-memory South Bridge initialization; module-specific',
      note: 'Exact activity depends on the platform firmware.'
    },

    '3E': {
      status: 'stage',
      meaning: 'Post-memory South Bridge initialization; module-specific',
      note: 'Exact activity depends on the platform firmware.'
    },

    '4F': {
      status: 'stage',
      meaning: 'DXE IPL started',
      note: 'Transition into later firmware initialization.'
    },

    '50': {
      status: 'error',
      meaning: 'Memory initialization error; invalid memory type or incompatible memory speed',
      note: 'Check memory compatibility, supported speeds, DIMM configuration, and motherboard documentation.'
    },

    '51': {
      status: 'error',
      meaning: 'Memory initialization error; SPD reading failed',
      note: 'Check DIMMs and whether the firmware can read their SPD information.'
    },

    '52': {
      status: 'error',
      meaning: 'Memory initialization error; invalid memory size or mismatched memory modules',
      note: 'Check DIMM capacity, population order, compatibility, and module matching.'
    },

    '53': {
      status: 'error',
      meaning: 'Memory initialization error; no usable memory detected',
      note: 'Check whether RAM is installed correctly and supported by the motherboard.'
    },

    '54': {
      status: 'error',
      meaning: 'Unspecified memory initialization error',
      note: 'Investigate RAM seating, compatibility, DIMM population, and firmware configuration.'
    },

    '55': {
      status: 'error',
      meaning: 'Memory not installed',
      note: 'Check that compatible DIMMs are installed and fully seated.'
    },

    '56': {
      status: 'error',
      meaning: 'Invalid CPU type or speed',
      note: 'Check CPU compatibility and firmware support for the processor.'
    },

    '57': {
      status: 'error',
      meaning: 'CPU mismatch',
      note: 'Check processor and platform compatibility.'
    },

    '58': {
      status: 'error',
      meaning: 'CPU self-test failed or possible CPU cache error',
      note: 'Check processor installation, compatibility, cooling, and motherboard diagnostics.'
    },

    '59': {
      status: 'error',
      meaning: 'CPU microcode not found or microcode update failed',
      note: 'Check firmware version and processor support.'
    },

    '5A': {
      status: 'error',
      meaning: 'Internal CPU error',
      note: 'Check processor installation, firmware support, cooling, and motherboard diagnostics.'
    },

    '5B': {
      status: 'error',
      meaning: 'Reset PPI is not available',
      note: 'Firmware-level initialization failure.'
    },

    '5C': {
      status: 'error',
      meaning: 'PEI phase BMC self-test failure',
      note: 'Relevant primarily to systems with a BMC/management controller.'
    },

    '60': {
      status: 'stage',
      meaning: 'DXE Core started',
      note: 'Normal DXE firmware initialization.'
    },

    '61': {
      status: 'stage',
      meaning: 'NVRAM initialization',
      note: 'Normal firmware configuration-store initialization.'
    },

    '62': {
      status: 'stage',
      meaning: 'South Bridge runtime services installation',
      note: 'Normal firmware initialization.'
    },

    '63': {
      status: 'stage',
      meaning: 'CPU DXE initialization started',
      note: 'Normal CPU-related DXE initialization.'
    },

    '64': {
      status: 'stage',
      meaning: 'CPU DXE initialization; module-specific',
      note: 'Exact activity depends on the firmware implementation.'
    },

    '65': {
      status: 'stage',
      meaning: 'CPU DXE initialization; module-specific',
      note: 'Exact activity depends on the firmware implementation.'
    },

    '66': {
      status: 'stage',
      meaning: 'CPU DXE initialization; module-specific',
      note: 'Exact activity depends on the firmware implementation.'
    },

    '67': {
      status: 'stage',
      meaning: 'CPU DXE initialization; module-specific',
      note: 'Exact activity depends on the firmware implementation.'
    },

    '68': {
      status: 'stage',
      meaning: 'PCI host bridge initialization',
      note: 'Normal PCI/platform initialization.'
    },

    '69': {
      status: 'stage',
      meaning: 'North Bridge DXE initialization started',
      note: 'Normal platform initialization.'
    },

    '6A': {
      status: 'stage',
      meaning: 'North Bridge DXE SMM initialization started',
      note: 'Normal firmware initialization.'
    },

    '6B': {
      status: 'stage',
      meaning: 'North Bridge DXE initialization; module-specific',
      note: 'Exact activity depends on the firmware implementation.'
    },

    '6C': {
      status: 'stage',
      meaning: 'North Bridge DXE initialization; module-specific',
      note: 'Exact activity depends on the firmware implementation.'
    },

    '6D': {
      status: 'stage',
      meaning: 'North Bridge DXE initialization; module-specific',
      note: 'Exact activity depends on the firmware implementation.'
    },

    '6E': {
      status: 'stage',
      meaning: 'North Bridge DXE initialization; module-specific',
      note: 'Exact activity depends on the firmware implementation.'
    },

    '6F': {
      status: 'stage',
      meaning: 'North Bridge DXE initialization; module-specific',
      note: 'Exact activity depends on the firmware implementation.'
    },

    '70': {
      status: 'stage',
      meaning: 'South Bridge DXE initialization started',
      note: 'Normal platform initialization.'
    },

    '71': {
      status: 'stage',
      meaning: 'South Bridge DXE SMM initialization started',
      note: 'Normal firmware initialization.'
    },

    '72': {
      status: 'stage',
      meaning: 'South Bridge devices initialization',
      note: 'Normal platform initialization.'
    },

    '73': {
      status: 'stage',
      meaning: 'South Bridge DXE initialization; module-specific',
      note: 'Exact activity depends on firmware implementation.'
    },

    '74': {
      status: 'stage',
      meaning: 'South Bridge DXE initialization; module-specific',
      note: 'Exact activity depends on firmware implementation.'
    },

    '75': {
      status: 'stage',
      meaning: 'South Bridge DXE initialization; module-specific',
      note: 'Exact activity depends on firmware implementation.'
    },

    '76': {
      status: 'stage',
      meaning: 'South Bridge DXE initialization; module-specific',
      note: 'Exact activity depends on firmware implementation.'
    },

    '77': {
      status: 'stage',
      meaning: 'South Bridge DXE initialization; module-specific',
      note: 'Exact activity depends on firmware implementation.'
    },

    '78': {
      status: 'stage',
      meaning: 'ACPI module initialization',
      note: 'Normal firmware initialization.'
    },

    '79': {
      status: 'stage',
      meaning: 'CSM initialization',
      note: 'Normal compatibility-support initialization on firmware that implements it.'
    },

    '90': {
      status: 'stage',
      meaning: 'Boot Device Selection phase started',
      note: 'Normal transition toward boot-device selection.'
    },

    '91': {
      status: 'stage',
      meaning: 'Driver connecting started',
      note: 'Firmware is connecting device drivers.'
    },

    '92': {
      status: 'stage',
      meaning: 'PCI bus initialization started',
      note: 'Normal PCI initialization.'
    },

    '93': {
      status: 'stage',
      meaning: 'PCI bus hot-plug controller initialization',
      note: 'Normal PCI-related initialization.'
    },

    '94': {
      status: 'stage',
      meaning: 'PCI bus enumeration',
      note: 'Firmware is enumerating PCI devices.'
    },

    '95': {
      status: 'stage',
      meaning: 'PCI bus request resources',
      note: 'Normal PCI resource allocation stage.'
    },

    '96': {
      status: 'stage',
      meaning: 'PCI bus assign resources',
      note: 'Normal PCI resource assignment stage.'
    },

    '97': {
      status: 'stage',
      meaning: 'Console output devices connect',
      note: 'Normal display/console initialization.'
    },

    '98': {
      status: 'stage',
      meaning: 'Console input devices connect',
      note: 'Normal keyboard/input-device initialization.'
    },

    '99': {
      status: 'stage',
      meaning: 'Super I/O initialization',
      note: 'Normal board-controller initialization.'
    },

    '9A': {
      status: 'stage',
      meaning: 'USB initialization started',
      note: 'Normal USB initialization.'
    },

    '9B': {
      status: 'stage',
      meaning: 'USB reset',
      note: 'Normal USB initialization checkpoint.'
    },

    '9C': {
      status: 'stage',
      meaning: 'USB detect',
      note: 'Normal USB device detection checkpoint.'
    },

    '9D': {
      status: 'stage',
      meaning: 'USB enable',
      note: 'Normal USB initialization checkpoint.'
    },

    'A0': {
      status: 'stage',
      meaning: 'IDE initialization started',
      note: 'Normal storage-controller initialization checkpoint.'
    },

    'A1': {
      status: 'stage',
      meaning: 'IDE reset',
      note: 'Normal storage-controller initialization checkpoint.'
    },

    'A2': {
      status: 'stage',
      meaning: 'IDE detect',
      note: 'This is a POST progress checkpoint, not inherently an error. If the machine hangs here, investigate storage devices, cables, ports, controller configuration, and the exact motherboard documentation.'
    },

    'A3': {
      status: 'stage',
      meaning: 'IDE enable',
      note: 'Normal storage-controller initialization checkpoint.'
    },

    'A4': {
      status: 'stage',
      meaning: 'SCSI initialization started',
      note: 'Normal storage-controller initialization checkpoint on systems using SCSI.'
    },

    'A5': {
      status: 'stage',
      meaning: 'SCSI reset',
      note: 'Normal SCSI initialization checkpoint.'
    },

    'A6': {
      status: 'stage',
      meaning: 'SCSI detect',
      note: 'Normal SCSI device-detection checkpoint.'
    },

    'A7': {
      status: 'stage',
      meaning: 'SCSI enable',
      note: 'Normal SCSI initialization checkpoint.'
    },

    'A8': {
      status: 'stage',
      meaning: 'Setup verifying password',
      note: 'Normal firmware setup checkpoint.'
    },

    'A9': {
      status: 'stage',
      meaning: 'Start of BIOS setup',
      note: 'Normal setup-entry checkpoint.'
    },

    'AB': {
      status: 'stage',
      meaning: 'Setup input wait',
      note: 'Firmware is waiting for setup input.'
    },

    'AD': {
      status: 'stage',
      meaning: 'Ready-to-boot event',
      note: 'Normal boot transition.'
    },

    'AE': {
      status: 'stage',
      meaning: 'Legacy Boot event',
      note: 'Normal legacy-boot transition on applicable firmware.'
    },

    'AF': {
      status: 'stage',
      meaning: 'Exit Boot Services event',
      note: 'Firmware is handing control to the operating system.'
    },

    'B0': {
      status: 'stage',
      meaning: 'Runtime Set Virtual Address Map Begin',
      note: 'Firmware runtime-services transition.'
    },

    'B1': {
      status: 'stage',
      meaning: 'Runtime Set Virtual Address Map End',
      note: 'Firmware runtime-services transition.'
    },

    'B2': {
      status: 'stage',
      meaning: 'Legacy Option ROM initialization',
      note: 'Normal legacy option-ROM initialization. On some boards a persistent B2 may indicate an external-device/option-ROM problem.'
    },

    'B3': {
      status: 'stage',
      meaning: 'System reset',
      note: 'Normal firmware reset checkpoint.'
    },

    'B4': {
      status: 'stage',
      meaning: 'USB hot plug',
      note: 'Normal USB hot-plug event.'
    },

    'B5': {
      status: 'stage',
      meaning: 'PCI bus hot plug',
      note: 'Normal PCI hot-plug event.'
    },

    'B6': {
      status: 'stage',
      meaning: 'Clean-up of NVRAM',
      note: 'Firmware is cleaning up configuration data.'
    },

    'B7': {
      status: 'stage',
      meaning: 'Configuration reset; NVRAM settings reset',
      note: 'Firmware configuration-reset checkpoint.'
    },

    'D0': {
      status: 'error',
      meaning: 'CPU initialization error',
      note: 'Check CPU installation, compatibility, firmware support, power delivery, and the exact motherboard diagnostics.'
    },

    'D1': {
      status: 'error',
      meaning: 'North Bridge initialization error',
      note: 'Platform initialization failed; consult the exact motherboard documentation.'
    },

    'D2': {
      status: 'error',
      meaning: 'South Bridge initialization error',
      note: 'Platform initialization failed; consult the exact motherboard documentation.'
    },

    'D3': {
      status: 'error',
      meaning: 'Some architectural protocols are not available',
      note: 'Firmware initialization failure.'
    },

    'D4': {
      status: 'error',
      meaning: 'PCI resource allocation error; out of resources',
      note: 'Check PCI/PCIe device configuration and resource allocation.'
    },

    'D5': {
      status: 'error',
      meaning: 'No space for Legacy Option ROM',
      note: 'Check legacy option-ROM usage and firmware configuration.'
    },

    'D6': {
      status: 'error',
      meaning: 'No console output devices found',
      note: 'Check graphics hardware and display initialization.'
    },

    'D7': {
      status: 'error',
      meaning: 'No console input devices found',
      note: 'Check keyboard/input-device initialization.'
    },

    'D8': {
      status: 'error',
      meaning: 'Invalid password',
      note: 'Firmware password validation failed.'
    },

    'D9': {
      status: 'error',
      meaning: 'Error loading boot option',
      note: 'Firmware LoadImage operation failed.'
    },

    'DA': {
      status: 'error',
      meaning: 'Boot option failed',
      note: 'Firmware StartImage operation failed.'
    },

    'DB': {
      status: 'error',
      meaning: 'Flash update failed',
      note: 'Firmware update operation failed.'
    },

    'DC': {
      status: 'error',
      meaning: 'Reset protocol is not available',
      note: 'Firmware initialization failure.'
    },

    'DD': {
      status: 'error',
      meaning: 'DXE phase BMC self-test failure',
      note: 'Applies primarily to systems with a BMC/management controller.'
    },

    'E0': {
      status: 'stage',
      meaning: 'S3 resume started',
      note: 'Sleep/resume firmware checkpoint.'
    },

    'E1': {
      status: 'stage',
      meaning: 'S3 boot-script execution',
      note: 'Sleep/resume firmware checkpoint.'
    },

    'E2': {
      status: 'stage',
      meaning: 'Video repost',
      note: 'Display hardware is being reinitialized after resume.'
    },

    'E3': {
      status: 'stage',
      meaning: 'OS S3 wake-vector call',
      note: 'Firmware is transitioning back to the operating system.'
    },

    'E8': {
      status: 'error',
      meaning: 'S3 resume failed',
      note: 'Resume from sleep state failed.'
    },

    'E9': {
      status: 'error',
      meaning: 'S3 Resume PPI not found',
      note: 'Firmware resume component was not found.'
    },

    'EA': {
      status: 'error',
      meaning: 'S3 Resume boot-script error',
      note: 'Firmware resume script failed.'
    },

    'EB': {
      status: 'error',
      meaning: 'S3 OS wake error',
      note: 'Operating-system wake transition failed.'
    },

    'F0': {
      status: 'warning',
      meaning: 'Recovery condition triggered by firmware',
      note: 'Firmware has entered or initiated recovery.'
    },

    'F1': {
      status: 'warning',
      meaning: 'Recovery condition triggered by user',
      note: 'Forced firmware recovery was requested.'
    },

    'F2': {
      status: 'stage',
      meaning: 'Recovery process started',
      note: 'Firmware recovery is in progress.'
    },

    'F3': {
      status: 'stage',
      meaning: 'Recovery firmware image found',
      note: 'Recovery image was located.'
    },

    'F4': {
      status: 'stage',
      meaning: 'Recovery firmware image loaded',
      note: 'Recovery image loading completed.'
    },

    'F8': {
      status: 'error',
      meaning: 'Recovery PPI is not available',
      note: 'Firmware recovery support component is unavailable.'
    },

    'F9': {
      status: 'error',
      meaning: 'Recovery capsule not found',
      note: 'Required firmware recovery image was not found.'
    },

    'FA': {
      status: 'error',
      meaning: 'Invalid recovery capsule',
      note: 'The firmware recovery image failed validation.'
    }
  },

  ASUS: {

    '00': {
      status: 'error',
      meaning: 'CPU abnormal / CPU initialization problem',
      note: 'ASUS lists 00 among common CPU-abnormal Q-Codes on applicable Intel boards. Check CPU compatibility, BIOS support, installation, and power.'
    },

    'D0': {
      status: 'error',
      meaning: 'CPU abnormal / CPU initialization problem',
      note: 'ASUS lists D0 among common CPU-abnormal Q-Codes on applicable Intel boards.'
    },

    '53': {
      status: 'error',
      meaning: 'Memory abnormal / memory initialization problem',
      note: 'ASUS lists 53 among common memory-abnormal Q-Codes on applicable boards. Check DIMM seating, memory compatibility, and population.'
    },

    '55': {
      status: 'error',
      meaning: 'Memory abnormal / memory initialization problem',
      note: 'ASUS lists 55 among common memory-abnormal Q-Codes. Check DIMM seating, supported memory configuration, and compatibility.'
    },

    'F9': {
      status: 'error',
      meaning: 'Memory abnormal / memory initialization problem',
      note: 'ASUS lists F9 among common AMD memory-abnormal Q-Codes on applicable boards.'
    },

    'D6': {
      status: 'error',
      meaning: 'Graphics initialization abnormal',
      note: 'ASUS lists D6 among common graphics-related Q-Codes. Check the graphics card, display connection, and applicable CPU/iGPU configuration.'
    },

    'B0': {
      status: 'warning',
      meaning: 'CPU/memory-related abnormal condition',
      note: 'ASUS lists B0 among common AMD CPU/memory troubleshooting Q-Codes.'
    },

    '99': {
      status: 'warning',
      meaning: 'CPU/memory-related abnormal condition',
      note: 'ASUS lists 99 among common AMD CPU/memory troubleshooting Q-Codes.'
    },

    '15': {
      status: 'warning',
      meaning: 'CPU/memory-related initialization abnormality',
      note: 'ASUS lists 15 among common AMD CPU/memory troubleshooting Q-Codes.'
    },

    '19': {
      status: 'warning',
      meaning: 'CPU/memory/graphics initialization abnormality',
      note: 'ASUS lists 19 among common AMD component-troubleshooting Q-Codes.'
    },

    '30': {
      status: 'warning',
      meaning: 'CPU/memory/graphics initialization abnormality',
      note: 'ASUS lists 30 among common AMD component-troubleshooting Q-Codes.'
    },

    '40': {
      status: 'warning',
      meaning: 'CPU/memory/graphics initialization abnormality',
      note: 'ASUS lists 40 among common AMD component-troubleshooting Q-Codes.'
    },

    'A0': {
      status: 'warning',
      meaning: 'Boot device abnormality / storage-related boot problem',
      note: 'ASUS lists A0 among common boot-device troubleshooting Q-Codes. Check SSD/HDD/NVMe devices and boot configuration.'
    },

    'A2': {
      status: 'warning',
      meaning: 'Boot device abnormality / storage-device detection stage',
      note: 'ASUS lists A2 among common boot-device troubleshooting Q-Codes. It does not necessarily mean a failed component; check storage devices and the exact board manual.'
    },

    'B2': {
      status: 'warning',
      meaning: 'External device abnormality',
      note: 'ASUS lists B2 among common external-device troubleshooting Q-Codes.'
    },

    'A9': {
      status: 'stage',
      meaning: 'Booting into BIOS setup',
      note: 'ASUS documents A9 as a BIOS-setup entry checkpoint, not inherently a hardware error.'
    },

    'AA': {
      status: 'success',
      meaning: 'Booted into the system',
      note: 'ASUS documents AA as a successful boot/system-entry state on applicable Q-Code boards.'
    }
  },

  Award: {

    '01': {
      status: 'stage',
      meaning: 'Processor test 1; processor status/flags verification',
      note: 'Award BIOS POST checkpoint.'
    },

    '02': {
      status: 'stage',
      meaning: 'Processor test 2; CPU register read/write verification',
      note: 'Award BIOS POST checkpoint.'
    },

    '03': {
      status: 'stage',
      meaning: 'Chip initialization; RTC, DMA, interrupt controllers, and related chipset initialization',
      note: 'Award BIOS POST checkpoint.'
    },

    '04': {
      status: 'stage',
      meaning: 'DRAM refresh test',
      note: 'Award BIOS POST checkpoint.'
    },

    '05': {
      status: 'stage',
      meaning: 'Video blanking and keyboard-controller initialization',
      note: 'Award BIOS POST checkpoint.'
    },

    '07': {
      status: 'stage',
      meaning: 'CMOS interface and battery-status test',
      note: 'Award BIOS POST checkpoint.'
    },

    '08': {
      status: 'stage',
      meaning: 'Low-memory setup / base-memory test',
      note: 'Award BIOS POST checkpoint.'
    },

    '09': {
      status: 'stage',
      meaning: 'CMOS RAM checksum test / default loading if invalid',
      note: 'Award BIOS POST checkpoint.'
    },

    '0A': {
      status: 'stage',
      meaning: 'Interrupt vector table setup',
      note: 'Award BIOS POST checkpoint.'
    },

    '0B': {
      status: 'stage',
      meaning: 'CMOS RAM checksum/default-value handling',
      note: 'Award BIOS POST checkpoint.'
    },

    '0C': {
      status: 'stage',
      meaning: 'Keyboard initialization and detection',
      note: 'Award BIOS POST checkpoint.'
    },

    '0D': {
      status: 'stage',
      meaning: 'Video adapter detection and initialization',
      note: 'Award BIOS POST checkpoint.'
    },

    '0E': {
      status: 'stage',
      meaning: 'Video-memory test and display/sign-on initialization',
      note: 'Award BIOS POST checkpoint.'
    },

    '0F': {
      status: 'stage',
      meaning: 'DMA controller 0 test',
      note: 'Award BIOS POST checkpoint.'
    },

    '10': {
      status: 'stage',
      meaning: 'DMA controller 1 test',
      note: 'Award BIOS POST checkpoint.'
    },

    '11': {
      status: 'stage',
      meaning: 'DMA page-register test',
      note: 'Award BIOS POST checkpoint.'
    },

    '14': {
      status: 'stage',
      meaning: 'System timer initialization/test',
      note: 'Award BIOS POST checkpoint; exact meaning varies by Award version/OEM.'
    },

    '18': {
      status: 'stage',
      meaning: 'System timer initialization',
      note: 'Award BIOS POST checkpoint; exact meaning varies by Award version/OEM.'
    },

    '1C': {
      status: 'stage',
      meaning: 'Memory refresh test',
      note: 'Award BIOS POST checkpoint.'
    },

    '20': {
      status: 'stage',
      meaning: 'Memory test',
      note: 'Award BIOS POST checkpoint.'
    },

    '24': {
      status: 'stage',
      meaning: 'Keyboard-controller test',
      note: 'Award BIOS POST checkpoint.'
    },

    '28': {
      status: 'stage',
      meaning: 'CPU descriptor/instruction test',
      note: 'Award BIOS POST checkpoint.'
    },

    '2C': {
      status: 'stage',
      meaning: 'Interrupt-controller setup/test',
      note: 'Award BIOS POST checkpoint.'
    },

    '30': {
      status: 'stage',
      meaning: 'Memory interrupt setup',
      note: 'Award BIOS POST checkpoint.'
    },

    '34': {
      status: 'stage',
      meaning: 'BIOS interrupt vectors and routines setup',
      note: 'Award BIOS POST checkpoint.'
    },

    '38': {
      status: 'stage',
      meaning: 'CMOS RAM test',
      note: 'Award BIOS POST checkpoint.'
    },

    '3C': {
      status: 'stage',
      meaning: 'Determine memory size',
      note: 'Award BIOS POST checkpoint.'
    },

    '3D': {
      status: 'stage',
      meaning: 'Mouse initialization/detection',
      note: 'Award BIOS POST checkpoint.'
    },

    '3E': {
      status: 'stage',
      meaning: 'Cache RAM test',
      note: 'Award BIOS POST checkpoint.'
    },

    '41': {
      status: 'stage',
      meaning: 'Floppy-drive initialization',
      note: 'Award BIOS POST checkpoint; applicable to legacy firmware.'
    },

    '42': {
      status: 'stage',
      meaning: 'Hard-drive initialization',
      note: 'Award BIOS POST checkpoint.'
    },

    '43': {
      status: 'stage',
      meaning: 'RS-232 / parallel-port initialization',
      note: 'Award BIOS POST checkpoint.'
    },

    '45': {
      status: 'stage',
      meaning: 'NPU / math-coprocessor initialization',
      note: 'Legacy Award BIOS checkpoint.'
    },

    '47': {
      status: 'stage',
      meaning: 'Processor-speed detection',
      note: 'Legacy Award BIOS checkpoint.'
    },

    '4E': {
      status: 'stage',
      meaning: 'Manufacturing loop',
      note: 'OEM/firmware-specific manufacturing checkpoint.'
    },

    '4F': {
      status: 'stage',
      meaning: 'Security check',
      note: 'Award BIOS checkpoint; exact behavior varies by OEM.'
    },

    '50': {
      status: 'stage',
      meaning: 'CMOS update',
      note: 'Award BIOS checkpoint.'
    },

    '51': {
      status: 'stage',
      meaning: 'Enable NMI',
      note: 'Award BIOS checkpoint.'
    },

    '52': {
      status: 'stage',
      meaning: 'Adapter ROM initialization',
      note: 'Award BIOS checkpoint.'
    },

    '53': {
      status: 'stage',
      meaning: 'Set time',
      note: 'Award BIOS checkpoint.'
    },

    '60': {
      status: 'stage',
      meaning: 'Set up BIOS interrupt routines',
      note: 'Award BIOS checkpoint.'
    },

    '64': {
      status: 'stage',
      meaning: 'Real-time clock test',
      note: 'Award BIOS checkpoint.'
    },

    '68': {
      status: 'stage',
      meaning: 'Diskette initialization',
      note: 'Legacy Award BIOS checkpoint.'
    },

    '6C': {
      status: 'stage',
      meaning: 'Hard-disk initialization/test',
      note: 'Legacy Award BIOS checkpoint.'
    },

    '70': {
      status: 'stage',
      meaning: 'Parallel-port initialization/test',
      note: 'Legacy Award BIOS checkpoint.'
    },

    '74': {
      status: 'stage',
      meaning: 'Serial-port initialization/test',
      note: 'Legacy Award BIOS checkpoint.'
    },

    '78': {
      status: 'stage',
      meaning: 'Set time of day',
      note: 'Award BIOS checkpoint.'
    },

    '7C': {
      status: 'stage',
      meaning: 'Scan for and invoke option ROMs',
      note: 'Award BIOS checkpoint.'
    },

    '80': {
      status: 'stage',
      meaning: 'Determine presence of math coprocessor',
      note: 'Legacy Award BIOS checkpoint.'
    },

    '84': {
      status: 'stage',
      meaning: 'Keyboard initialization',
      note: 'Legacy Award BIOS checkpoint.'
    },

    'B0': {
      status: 'stage',
      meaning: 'NMI in protected mode',
      note: 'Legacy Award BIOS checkpoint.'
    },

    'B1': {
      status: 'stage',
      meaning: 'Disable NMI',
      note: 'Legacy Award BIOS checkpoint.'
    },

    'BE': {
      status: 'stage',
      meaning: 'Chipset default initialization',
      note: 'Award BIOS checkpoint.'
    },

    'BF': {
      status: 'stage',
      meaning: 'Chipset programming',
      note: 'Award BIOS checkpoint.'
    },

    'C0': {
      status: 'stage',
      meaning: 'Turn off chipset cache / early chipset initialization',
      note: 'Award BIOS checkpoint; exact behavior varies by Award version/OEM.'
    },

    'C1': {
      status: 'stage',
      meaning: 'Memory detection / memory sizing',
      note: 'Award BIOS checkpoint.'
    },

    'C2': {
      status: 'stage',
      meaning: 'Base 256K memory test',
      note: 'Legacy Award BIOS checkpoint.'
    },

    'C3': {
      status: 'stage',
      meaning: 'Expand compressed BIOS code to DRAM',
      note: 'Award BIOS checkpoint.'
    },

    'C4': {
      status: 'stage',
      meaning: 'Video switch',
      note: 'Legacy Award BIOS checkpoint.'
    },

    'C5': {
      status: 'stage',
      meaning: 'Copy BIOS to shadow RAM',
      note: 'Award BIOS checkpoint.'
    },

    'C6': {
      status: 'stage',
      meaning: 'Cache presence test',
      note: 'Award BIOS checkpoint.'
    },

    'C8': {
      status: 'stage',
      meaning: 'Speed-switch processing',
      note: 'Legacy Award BIOS checkpoint.'
    },

    'C9': {
      status: 'stage',
      meaning: 'Shadow-RAM processing',
      note: 'Legacy/OEM-specific Award BIOS checkpoint.'
    },

    'CA': {
      status: 'stage',
      meaning: 'OEM chipset initialization',
      note: 'OEM-specific Award BIOS checkpoint.'
    },

    'CF': {
      status: 'stage',
      meaning: 'CMOS read/write functionality test',
      note: 'Award BIOS checkpoint.'
    }
  }

};

const BEEP_CODES = {

  Dell: {

    '1-1-2': {
      status: 'error',
      meaning: 'Microprocessor register failure',
      note: 'Check CPU/platform diagnostics and the exact Dell service documentation for the system model.'
    },

    '1-1-3': {
      status: 'error',
      meaning: 'NVRAM read/write failure',
      note: 'The firmware could not properly access nonvolatile configuration memory.'
    },

    '1-1-4': {
      status: 'error',
      meaning: 'ROM BIOS checksum failure',
      note: 'The BIOS/firmware checksum did not validate.'
    },

    '1-2-1': {
      status: 'error',
      meaning: 'Programmable interval timer failure',
      note: 'Firmware timer initialization/test failed.'
    },

    '1-2-2': {
      status: 'error',
      meaning: 'DMA initialization failure',
      note: 'Direct-memory-access controller initialization failed.'
    },

    '1-2-3': {
      status: 'error',
      meaning: 'DMA page-register read/write failure',
      note: 'Firmware could not successfully test the DMA page registers.'
    },

    '1-3': {
      status: 'error',
      meaning: 'Video memory test failure',
      note: 'Check the graphics subsystem and the exact Dell model diagnostics.'
    },

    '1-3-1': {
      status: 'error',
      meaning: 'Memory modules not being properly identified or used',
      note: 'Dell documents this pattern as part of a range of memory-related beep conditions.'
    },

    '1-3-2': {
      status: 'error',
      meaning: 'Memory failure',
      note: 'Dell uses this pattern on documented systems for memory failure. Check RAM seating, DIMM compatibility, and the exact model documentation.'
    },

    '1-3-3': {
      status: 'error',
      meaning: 'Memory modules not being properly identified or used',
      note: 'Part of Dells documented memory-beep range on applicable legacy systems.'
    },

    '1-3-4': {
      status: 'error',
      meaning: 'Memory modules not being properly identified or used',
      note: 'Part of Dells documented memory-beep range on applicable legacy systems.'
    },

    '1-4': {
      status: 'error',
      meaning: 'Memory modules not being properly identified or used',
      note: 'Dell documents this within legacy memory-related beep-code families.'
    },

    '2-1': {
      status: 'error',
      meaning: 'Memory modules not being properly identified or used',
      note: 'Applicable to certain Dell legacy beep-code schemes.'
    },

    '2-2': {
      status: 'error',
      meaning: 'Memory modules not being properly identified or used',
      note: 'Applicable to certain Dell legacy beep-code schemes.'
    },

    '2-3': {
      status: 'error',
      meaning: 'Memory modules not being properly identified or used',
      note: 'Applicable to certain Dell legacy beep-code schemes.'
    },

    '2-4': {
      status: 'error',
      meaning: 'Memory modules not being properly identified or used',
      note: 'Applicable to certain Dell legacy beep-code schemes.'
    },

    '3-1-1': {
      status: 'error',
      meaning: 'Slave DMA register failure',
      note: 'Firmware failed the slave DMA register test.'
    },

    '3-1-2': {
      status: 'error',
      meaning: 'Master DMA register failure',
      note: 'Firmware failed the master DMA register test.'
    },

    '3-1-3': {
      status: 'error',
      meaning: 'Master interrupt mask register failure',
      note: 'Firmware failed the master interrupt-mask register test.'
    },

    '3-1-4': {
      status: 'error',
      meaning: 'Slave interrupt mask register failure',
      note: 'Firmware failed the slave interrupt-mask register test.'
    },

    '3-2-2': {
      status: 'error',
      meaning: 'Interrupt vector loading failure',
      note: 'Firmware could not correctly load the interrupt vectors.'
    },

    '3-2-4': {
      status: 'error',
      meaning: 'Keyboard controller test failure',
      note: 'Check the keyboard/controller path and motherboard diagnostics.'
    },

    '3-3-1': {
      status: 'error',
      meaning: 'NVRAM power loss',
      note: 'Check CMOS/NVRAM power and the applicable Dell system documentation.'
    },

    '3-3-2': {
      status: 'error',
      meaning: 'Invalid NVRAM configuration',
      note: 'Firmware configuration stored in NVRAM is invalid or could not be initialized.'
    },

    '3-3-3': {
      status: 'error',
      meaning: 'Real-time clock or keyboard controller not found',
      note: 'Check the RTC/CMOS and keyboard-controller subsystem.'
    },

    '3-3-4': {
      status: 'error',
      meaning: 'Video memory test failure',
      note: 'Check the graphics subsystem and exact Dell model documentation.'
    },

    '3-4-1': {
      status: 'error',
      meaning: 'Screen initialization failure',
      note: 'Check graphics hardware, display connection, and model-specific diagnostics.'
    },

    '3-4-2': {
      status: 'error',
      meaning: 'Screen retrace failure',
      note: 'Graphics initialization/retrace test failed.'
    },

    '3-4-3': {
      status: 'error',
      meaning: 'Search for video ROM failure',
      note: 'Firmware could not locate or initialize the expected video ROM.'
    },

    '4-2-1': {
      status: 'error',
      meaning: 'Timer tick failure',
      note: 'System timer test failed.'
    },

    '4-2-2': {
      status: 'error',
      meaning: 'Shutdown failure',
      note: 'Firmware shutdown test failed.'
    },

    '4-2-3': {
      status: 'error',
      meaning: 'Gate A20 failure',
      note: 'Legacy CPU/memory-addressing initialization failed.'
    },

    '4-2-4': {
      status: 'error',
      meaning: 'Unexpected interrupt in protected mode',
      note: 'A protected-mode interrupt condition occurred unexpectedly.'
    },

    '4-3-1': {
      status: 'error',
      meaning: 'Memory failure above address 0FFFFh',
      note: 'Firmware detected a memory failure above the lower memory boundary.'
    },

    '4-3-3': {
      status: 'error',
      meaning: 'Timer-chip counter 2 failure',
      note: 'Legacy system timer hardware test failed.'
    },

    '4-3-4': {
      status: 'error',
      meaning: 'Time-of-day clock stopped',
      note: 'Check RTC/CMOS battery and motherboard clock hardware.'
    },

    '4-4-1': {
      status: 'error',
      meaning: 'Serial or parallel port test failure',
      note: 'Legacy I/O port testing failed.'
    },

    '4-4-2': {
      status: 'error',
      meaning: 'Failure to decompress code to shadowed memory',
      note: 'Firmware failed a legacy BIOS decompression/shadowing operation.'
    },

    '4-4-3': {
      status: 'error',
      meaning: 'Math-coprocessor test failure',
      note: 'Legacy processor/math-coprocessor initialization failed.'
    },

    '4-4-4': {
      status: 'error',
      meaning: 'Cache test failure',
      note: 'Processor cache test failed.'
    }
  }
};

function normalizeBeepPattern(text) {
  const input = String(text ?? '')
    .trim()
    .toLowerCase();

  if (!input) return null;

  /*
   * First, look for an explicit numeric sequence.
   *
   * Examples:
   *   1-3-2
   *   1 3 2
   *   1,3,2
   *   1 / 3 / 2
   */
  const explicit = input.match(
    /\b\d+(?:\s*[-–—,\/+x]\s*\d+)+\b/
  );

  if (explicit) {
    return explicit[0]
      .replace(/[–—]/g, '-')
      .replace(/[,\s\/+x]+/gi, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
  }

  const numbers = [
    ...input.matchAll(/\b\d+\b/g)
  ].map(m => m[0]);

  if (numbers.length >= 2) {
    return numbers.join('-');
  }

  return null;
}

function lookupBeepCode(pattern, vendor) {
  const normalized = normalizeBeepPattern(pattern);

  if (!normalized) return null;

  /*
   * Explicit vendor selection.
   */
  if (vendor && vendor !== 'auto') {
    const entry = BEEP_CODES[vendor]?.[normalized];

    if (entry) {
      return {
        ...entry,
        vendor,
        pattern: normalized
      };
    }
  }

  /*
   * Auto-search all available vendor databases.
   */
  const matches = [];

  for (const [vendorName, codes] of Object.entries(BEEP_CODES)) {
    const entry = codes[normalized];

    if (entry) {
      matches.push({
        ...entry,
        vendor: vendorName,
        pattern: normalized
      });
    }
  }

  if (matches.length === 1) {
    return matches[0];
  }

  if (matches.length > 1) {
    return {
      status: 'ambiguous',
      pattern: normalized,
      meaning:
        'This beep pattern exists for more than one vendor/system family and needs the exact model to determine its meaning.',
      matches
    };
  }

  return null;
}

function esc(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function $(sel, root = document) {
  return root.querySelector(sel);
}

function copyText(text) {
  if (navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(text);
  }

  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  document.execCommand('copy');
  ta.remove();

  return Promise.resolve();
}

function detectVendor(text) {
  for (const [name, re] of VENDOR_HINTS) {
    if (re.test(text)) return name;
  }

  return null;
}

function normalizeCode(code) {
  return String(code ?? '')
    .trim()
    .toUpperCase()
    .replace(/^0X/, '');
}

function lookupPostCode(code, vendor) {
  const normalized = normalizeCode(code);

  if (!normalized) return null;

  /*
   * If the user explicitly selected a vendor, prefer that vendor.
   */
  if (vendor && vendor !== 'auto') {
    const entry = POST_CODES[vendor]?.[normalized];

    if (entry) {
      return {
        ...entry,
        vendor
      };
    }
  }

  /*
   * Auto-detect / search all vendors.
   */
  const matches = [];

  for (const [vendorName, codes] of Object.entries(POST_CODES)) {
    const entry = codes[normalized];

    if (entry) {
      matches.push({
        ...entry,
        vendor: vendorName
      });
    }
  }

  if (matches.length === 1) {
    return matches[0];
  }

  if (matches.length > 1) {
    return {
      status: 'ambiguous',
      meaning: 'This code exists in the local database, but its meaning depends on the firmware/vendor.',
      matches
    };
  }

  return null;
}

function statusBadgeClass(status) {
  switch (status) {
    case 'error':
      return 'error';

    case 'warning':
      return 'warning';

    case 'stage':
      return 'stage';

    case 'success':
      return 'ok';

    default:
      return '';
  }
}

function getVerdict(known) {
  if (!known) {
    return 'Code structure identified, but this local database has no verified meaning for this code.';
  }

  switch (known.status) {
    case 'error':
      return `Known error: ${known.meaning}`;

    case 'warning':
      return `Known warning/diagnostic condition: ${known.meaning}`;

    case 'stage':
      return `POST progress stage: ${known.meaning}. This is not inherently an error.`;

    case 'success':
      return `Known normal/success state: ${known.meaning}.`;

    case 'ambiguous':
      return 'This code is known locally, but its meaning differs between vendors or firmware implementations.';

    default:
      return known.meaning || 'Known diagnostic code.';
  }
}

function detectBeep(text, vendor = 'auto') {
  const input = String(text ?? '')
    .trim()
    .replace(/\s+/g, ' ');

  if (!input) return null;

  const hasBeepWord =
    /\b(beeps?|beep|tones?|tone)\b/i.test(input);

  const hasPatternWords =
    /\b(long|short)\b/i.test(input);

  const hasNumericSequence =
    /\b\d+(?:\s*[-–—,\/+x]\s*\d+)+\b/i.test(input);

  const hasNumberedBeepWording =
    /\b\d+\s*(?:beeps?|tones?)\b/i.test(input);

  /*
   * Don't classify ordinary text as a beep code.
   */
  if (
    !hasBeepWord &&
    !hasPatternWords &&
    !hasNumericSequence
  ) {
    return null;
  }

  const numbers = [
    ...input.matchAll(/\b\d+\b/g)
  ].map(m => m[0]);

  const toneWords = [
    ...input.matchAll(
      /\b(?:long|short|beep|beeps|tone|tones)\b/gi
    )
  ].map(m => m[0].toLowerCase());

  const normalized = normalizeBeepPattern(input);

  const known = normalized
    ? lookupBeepCode(normalized, vendor)
    : null;

  const parts = [];

  parts.push({
    label: 'Pattern text',
    value: input,
    meaning: 'Original beep/tone wording supplied by the user'
  });

  if (normalized) {
    parts.push({
      label: 'Normalized beep pattern',
      value: normalized,
      meaning: 'Canonical form used for local database lookup'
    });
  }

  if (numbers.length) {
    parts.push({
      label: 'Numbers',
      value: numbers.join(', '),
      meaning: 'Numeric counts detected in the beep/tone description'
    });
  }

  if (toneWords.length) {
    parts.push({
      label: 'Tone words',
      value: [...new Set(toneWords)].join(', '),
      meaning: 'Long/short/beep/tone descriptors detected in the input'
    });
  }

  if (known) {

    if (known.status === 'ambiguous') {
      parts.push({
        label: 'Local database status',
        value: STATUS_LABELS.ambiguous,
        meaning:
          'More than one vendor/system family has a matching local entry'
      });
    } else {
      parts.push({
        label: 'Local database status',
        value:
          STATUS_LABELS[known.status] ||
          STATUS_LABELS.unknown,
        meaning:
          'Status returned by the browser-local beep-code database'
      });

      if (known.vendor) {
        parts.push({
          label: 'Matched vendor',
          value: known.vendor,
          meaning:
            'Vendor associated with the local database entry'
        });
      }

      if (known.meaning) {
        parts.push({
          label: 'Known meaning',
          value: known.meaning,
          meaning:
            'Meaning stored in the browser-local database'
        });
      }
    }

  } else if (normalized) {

    parts.push({
      label: 'Local database status',
      value: STATUS_LABELS.unknown,
      meaning:
        'The normalized beep pattern was not found in the local database'
    });
  }

  let verdict;

  if (!normalized) {

    verdict =
      'A beep/tone pattern was detected, but a reliable numeric beep sequence could not be extracted. Enter the number of beeps in each group, such as 1-3-2.';

  } else if (!known) {

    verdict =
      `Beep pattern ${normalized} detected, but this local database has no verified meaning for it. Do not treat an unknown pattern as a confirmed error.`;

  } else if (known.status === 'ambiguous') {

    verdict =
      `Beep pattern ${normalized} is known, but its meaning depends on the vendor/system family.`;

  } else if (known.status === 'error') {

    verdict =
      `Known error: ${known.meaning}`;

  } else if (known.status === 'warning') {

    verdict =
      `Known warning/diagnostic condition: ${known.meaning}`;

  } else if (known.status === 'stage') {

    verdict =
      `POST progress stage: ${known.meaning}. This is not inherently an error.`;

  } else if (known.status === 'success') {

    verdict =
      `Known normal/success state: ${known.meaning}`;

  } else {

    verdict =
      known.meaning ||
      'Known diagnostic beep pattern.';
  }

  const searchTerms = [
    input
  ];

  if (normalized) {
    searchTerms.push(
      `BIOS beep code ${normalized}`
    );

    searchTerms.push(
      `POST beep code ${normalized}`
    );
  }

  if (vendor && vendor !== 'auto') {
    searchTerms.push(
      `${vendor} beep code ${normalized || input}`
    );

    searchTerms.push(
      `${vendor} POST beep code ${normalized || input}`
    );
  }

  searchTerms.push(
    'exact motherboard or computer model'
  );

  return {
    family: 'beep',
    vendor,
    known,
    normalizedPattern: normalized,
    verdict,
    parts,
    searchTerms: [...new Set(searchTerms)]
  };
}

function splitCode(token) {
  const parts = [];

  const prefix = token.match(/^([A-Za-z]{1,8})(?=[-_:.]?\d)/);

  if (prefix) {
    parts.push({
      label: 'Letter prefix',
      value: prefix[1],
      meaning: 'Prefix/mnemonic/vendor marker; meaning is vendor-specific'
    });
  }

  const separators = [
    ...token.matchAll(/[-_:.\/#]+/g)
  ].map(m => m[0]);

  if (separators.length) {
    parts.push({
      label: 'Separator(s)',
      value: [...new Set(separators)].join('  '),
      meaning: 'Formatting separators; generally not meaningful alone'
    });
  }

  const hex = token.match(/(?:0x)?([0-9A-Fa-f]{2,8})$/);

  if (hex && /[A-Fa-f]/.test(hex[1])) {
    parts.push({
      label: 'Hex-looking portion',
      value: hex[0],
      meaning: 'Hex-looking component; interpretation depends on BIOS/vendor'
    });
  }

  const numeric = token.match(
    /(?:^|[-_:.#])(\d{1,8})(?:$|[-_:.#])/
  );

  if (numeric) {
    parts.push({
      label: 'Numeric portion',
      value: numeric[1],
      meaning: 'Numeric diagnostic value; interpretation depends on code family'
    });
  }

  const suffix = token.match(/[-_:.#]([A-Za-z]{1,8})$/);

  if (suffix) {
    parts.push({
      label: 'Suffix',
      value: suffix[1],
      meaning: 'Trailing mnemonic/vendor-specific component'
    });
  }

  if (!parts.length) {
    parts.push({
      label: 'Raw token',
      value: token,
      meaning: 'No standard substructure confidently recognized'
    });
  }

  return parts;
}

function buildSearchTerms(input, vendor, family, parts) {
  const set = new Set([input]);

  if (vendor) {
    set.add(`${vendor} ${input}`);
  }

  const primary = parts.find(
    p => p.label === 'Primary code'
  );

  if (primary) {
    set.add(`BIOS POST ${primary.value}`);
    set.add(`POST code ${primary.value}`);

    if (vendor) {
      set.add(`${vendor} POST code ${primary.value}`);
    }
  }

  if (family === 'beep') {
    set.add(`BIOS beep code ${input}`);

    if (vendor) {
      set.add(`${vendor} beep code ${input}`);
    }
  }

  return [...set];
}

function analyze(raw, vendorChoice) {
  const input = raw.trim().replace(/\s+/g, ' ');

  if (!input) {
    return {
      status: 'empty'
    };
  }

  const vendor =
    vendorChoice !== 'auto'
      ? vendorChoice
      : detectVendor(input);

  const beep = detectBeep(input);

  if (beep) {
    return {
      status: 'ok',
      family: beep.family,
      vendor,
      known: null,
      verdict:
        'This looks like a beep/tone POST pattern. This tool does not infer a universal fault from the tone sequence; search the exact sequence with the system or motherboard model.',
      parts: beep.parts,
      searchTerms: buildSearchTerms(
        input,
        vendor,
        beep.family,
        beep.parts
      )
    };
  }

  const tokens = input.split(/\s+/);

  const codeToken = tokens.find(t =>
    /^(?:0x)?[0-9A-Fa-f]{2,8}$/.test(t) ||
    /^[A-Za-z]{1,8}[-_:.#]?\d{1,8}[A-Za-z0-9_-]*$/i.test(t)
  );

  let family = 'text';

  if (codeToken) {
    if (
      /^(?:0x)?[0-9A-Fa-f]{2,8}$/i.test(codeToken) &&
      /[A-Fa-f]/.test(codeToken)
    ) {
      family = codeToken.length >= 4
        ? 'hex'
        : 'qcode';
    } else if (/^\d+$/.test(codeToken)) {
      family = codeToken.length <= 2
        ? 'qcode'
        : 'decimal';
    } else {
      family = 'branded';
    }
  }

  const parts = [];

  let known = null;

  if (codeToken) {
    known = lookupPostCode(
      codeToken,
      vendor
    );

    parts.push({
      label: 'Primary code',
      value: codeToken,
      meaning:
        'Token that most resembles a BIOS/POST diagnostic code'
    });

    parts.push(
      ...splitCode(codeToken)
    );

    if (known) {
      parts.push({
        label: 'Local database status',
        value:
          STATUS_LABELS[known.status] ||
          STATUS_LABELS.unknown,
        meaning:
          'Status from the browser-local POST code database'
      });

      if (
        known.vendor &&
        vendor === 'auto'
      ) {
        parts.push({
          label: 'Matched vendor',
          value: known.vendor,
          meaning:
            'Vendor associated with the local database entry'
        });
      }
    }

    const context = tokens
      .filter(t => t !== codeToken)
      .join(' ');

    if (context) {
      parts.push({
        label: 'Context text',
        value: context,
        meaning:
          'Keep this context when searching the exact vendor message'
      });
    }
  } else {
    parts.push({
      label: 'Full message',
      value: input,
      meaning:
        'No compact code token was confidently identified'
    });
  }

  return {
    status: 'ok',
    family,
    vendor,
    known,
    verdict: known
      ? getVerdict(known)
      : codeToken
        ? 'Code structure identified, but this local database has no verified meaning for it. Do not label it as an error based on its format alone.'
        : 'This looks more like a BIOS/UEFI text message. Search the exact wording with the vendor and system/motherboard model.',
    parts,
    searchTerms: buildSearchTerms(
      input,
      vendor,
      family,
      parts
    )
  };
}

function renderKnownResult(result) {
  if (!result.known) {
    return `
      <div class="card">
        <h3>Verification status</h3>
        <p class="muted">
          No verified local database entry was found for this code.
          The tool will not label it as an error based only on its format.
        </p>
      </div>
    `;
  }

  const known = result.known;

  if (known.status === 'ambiguous') {
    return `
      <div class="card">
        <h3>Known code — vendor dependent</h3>

        <div class="row">
          <span class="badge">
            ${esc(STATUS_LABELS.ambiguous)}
          </span>
        </div>

        <p>
          ${esc(known.meaning || '')}
        </p>

        ${
          known.matches?.length
            ? `
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Vendor</th>
                      <th>Status</th>
                      <th>Meaning</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${known.matches.map(match => `
                      <tr>
                        <td>${esc(match.vendor)}</td>
                        <td>
                          <span class="badge ${statusBadgeClass(match.status)}">
                            ${esc(
                              STATUS_LABELS[match.status] ||
                              STATUS_LABELS.unknown
                            )}
                          </span>
                        </td>
                        <td>${esc(match.meaning || '')}</td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              </div>
            `
            : ''
        }
      </div>
    `;
  }

  const badgeClass = statusBadgeClass(
    known.status
  );

  return `
    <div class="card">
      <h3>Known meaning</h3>

      <div class="row">
        <span class="badge ${badgeClass}">
          ${esc(
            STATUS_LABELS[known.status] ||
            STATUS_LABELS.unknown
          )}
        </span>

        ${
          known.vendor
            ? `<span class="badge">${esc(known.vendor)}</span>`
            : ''
        }
      </div>

      <p>
        <strong>${esc(known.meaning || '')}</strong>
      </p>

      ${
        known.note
          ? `<p class="muted">${esc(known.note)}</p>`
          : ''
      }
    </div>
  `;
}

function renderResult(app, result) {
  const resultEl = $('#bios-result', app);

  if (result.status === 'empty') {
    resultEl.innerHTML = '';
    return;
  }

  resultEl.innerHTML = `
    <div class="card">
      <div class="row between">
        <div>
          <h3>Quick interpretation</h3>
          <p>${esc(result.verdict)}</p>
        </div>

        <div class="row">
          <span class="badge">
            ${esc(
              FAMILY_LABELS[result.family] ||
              FAMILY_LABELS.unknown
            )}
          </span>

          ${
            result.vendor
              ? `<span class="badge ok">${esc(result.vendor)}</span>`
              : ''
          }
        </div>
      </div>
    </div>

    ${renderKnownResult(result)}

    <div class="card">
      <h3>How the code is built</h3>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Part</th>
              <th>Value</th>
              <th>Meaning for search</th>
            </tr>
          </thead>

          <tbody>
            ${result.parts.map(p => `
              <tr>
                <td>${esc(p.label)}</td>
                <td><code>${esc(p.value)}</code></td>
                <td>${esc(p.meaning)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="row between">
        <div>
          <h3>Search-ready queries</h3>
          <p class="muted">
            Add the exact computer/motherboard model
            for better results.
          </p>
        </div>

        <button
          class="btn secondary"
          type="button"
          id="bios-copy-search"
        >
          Copy all
        </button>
      </div>

      ${result.searchTerms.map((term, i) => `
        <div
          class="row between search-term"
          style="gap:.75rem;margin:.35rem 0"
        >
          <code>${esc(term)}</code>

          <button
            class="btn secondary"
            type="button"
            data-copy-term="${i}"
          >
            Copy
          </button>
        </div>
      `).join('')}
    </div>

    <div class="card">
      <h3>Important limitation</h3>

      <p class="muted">
        BIOS/UEFI POST codes are vendor-, model-, generation-,
        firmware-, and display-specific. A code can be a normal
        POST progress stage on one system and have a different
        meaning on another. This tool only labels a code as an
        error when the local database contains an explicit
        <code>error</code> entry.
      </p>
    </div>
  `;

  $('#bios-copy-search', app).addEventListener(
    'click',
    async () => {
      await copyText(
        result.searchTerms.join('\n')
      );

      flash(
        app,
        'Search queries copied.'
      );
    }
  );

  app
    .querySelectorAll('[data-copy-term]')
    .forEach(btn => {
      btn.addEventListener(
        'click',
        async () => {
          await copyText(
            result.searchTerms[
              Number(btn.dataset.copyTerm)
            ]
          );

          flash(app, 'Copied.');
        }
      );
    });
}

function flash(app, text) {
  const el = $('#bios-message', app);

  el.className = 'notice success';
  el.textContent = text;

  clearTimeout(el._timer);

  el._timer = setTimeout(() => {
    el.className = 'notice hidden';
    el.textContent = '';
  }, 2200);
}

export function renderBiosInterpreter(app) {
  app.innerHTML = `
    <section class="card">
      <div class="row between">
        <div>
          <h2>BIOS / POST Error Interpreter</h2>

          <p class="muted">
            Break a BIOS/UEFI diagnostic code into searchable parts and, when available, compare it with the browser-local POST code database.
          </p>
        </div>

        <span class="muted">
          LOCAL ONLY
        </span>
      </div>

      <div class="grid two">
        <div>
          <label for="bios-code">
            BIOS / POST code or message
          </label>

          <input
            id="bios-code"
            type="text"
            placeholder="e.g. A2, 0x55, 1-3-2, 9C, memory initialization"
            autocomplete="off"
            spellcheck="false"
          >
        </div>

        <div>
          <label for="bios-vendor">
            Vendor hint
          </label>

          <select id="bios-vendor">
            <option value="auto">
              Auto-detect
            </option>

            <option value="AMI">
              AMI / American Megatrends
            </option>

            <option value="Award">
              Award
            </option>

            <option value="Phoenix">
              Phoenix
            </option>

            <option value="Dell">
              Dell
            </option>

            <option value="HP">
              HP
            </option>

            <option value="Lenovo">
              Lenovo
            </option>

            <option value="ASUS">
              ASUS
            </option>

            <option value="MSI">
              MSI
            </option>

            <option value="Gigabyte">
              Gigabyte
            </option>
          </select>
        </div>
      </div>

      <div class="row">
        <button
          class="btn"
          type="button"
          id="bios-analyze"
        >
          Analyze
        </button>

        <button
          class="btn secondary"
          type="button"
          id="bios-example"
        >
          Load example
        </button>

        <button
          class="btn secondary"
          type="button"
          id="bios-clear"
        >
          Clear
        </button>
      </div>

      <div
        id="bios-message"
        class="notice hidden"
        role="status"
      ></div>

      <div id="bios-result"></div>

      <div class="card">
        <h3>Privacy / scope</h3>

        <p class="muted">
          The entered code never leaves the browser. No DNS
          request, lookup, search-engine query, vendor website
          request, API call, or reputation service is used.
          All code interpretation is performed locally.
        </p>
      </div>
    </section>
  `;

  const code = $('#bios-code', app);
  const vendor = $('#bios-vendor', app);

  const analyzeNow = () => {
    renderResult(
      app,
      analyze(
        code.value,
        vendor.value
      )
    );
  };

  $('#bios-analyze', app)
    .addEventListener(
      'click',
      analyzeNow
    );

  code.addEventListener(
    'keydown',
    e => {
      if (e.key === 'Enter') {
        analyzeNow();
      }
    }
  );

  $('#bios-example', app)
    .addEventListener(
      'click',
      () => {
        code.value = 'A2';
        vendor.value = 'auto';
        analyzeNow();
      }
    );

  $('#bios-clear', app)
    .addEventListener(
      'click',
      () => {
        code.value = '';

        $('#bios-result', app).innerHTML = '';

        $('#bios-message', app).className =
          'notice hidden';

        $('#bios-message', app).textContent = '';
      }
    );
}