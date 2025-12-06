// API endpoint for LFI vulnerability testing
// This allows CLI scanners to detect the vulnerability

export default function handler(req, res) {
    // Enable CORS for scanner
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS')

    if (req.method === 'OPTIONS') {
        return res.status(200).end()
    }

    const { file } = req.query

    if (!file) {
        return res.status(200).send('No file specified')
    }

    // VULNERABLE: Path traversal detection
    const hasPathTraversal = file.includes('../') ||
        file.includes('....//') ||
        file.includes('..\\') ||
        file.includes('%2e%2e') ||
        file.includes('%2e%2e%2f') ||
        file.includes('..%2f') ||
        file.includes('..%5c') ||
        file.includes('%252f') ||
        file.includes('%255c')

    const isEtcPasswd = file.toLowerCase().includes('etc/passwd') ||
        file.toLowerCase().includes('etc\\passwd') ||
        file.toLowerCase().includes('/etc/passwd')

    const isEtcShadow = file.toLowerCase().includes('etc/shadow') ||
        file.toLowerCase().includes('/etc/shadow')

    const isProcVersion = file.toLowerCase().includes('proc/version') ||
        file.toLowerCase().includes('/proc/version')

    const isProcCpuinfo = file.toLowerCase().includes('proc/cpuinfo') ||
        file.toLowerCase().includes('/proc/cpuinfo')

    const isWinIni = file.toLowerCase().includes('windows') &&
        file.toLowerCase().includes('win.ini')

    // Simulate LFI vulnerability - return file content with clear indicators
    if (hasPathTraversal && isEtcPasswd) {
        // Return simulated /etc/passwd content with clear LFI indicators
        res.setHeader('Content-Type', 'text/plain')
        return res.status(200).send(`root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
`)
    }

    if (hasPathTraversal && isEtcShadow) {
        // Return simulated /etc/shadow content
        res.setHeader('Content-Type', 'text/plain')
        return res.status(200).send(`root:$6$xyz$hashedpassword:18000:0:99999:7:::
daemon:*:18000:0:99999:7:::
bin:*:18000:0:99999:7:::
sys:*:18000:0:99999:7:::
`)
    }

    if (hasPathTraversal && isProcVersion) {
        // Return simulated /proc/version content
        res.setHeader('Content-Type', 'text/plain')
        return res.status(200).send(`Linux version 5.10.0-21-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.162-1 (2023-01-21)
`)
    }

    if (hasPathTraversal && isProcCpuinfo) {
        // Return simulated /proc/cpuinfo content
        res.setHeader('Content-Type', 'text/plain')
        return res.status(200).send(`processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 142
model name	: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
`)
    }

    if (hasPathTraversal && isWinIni) {
        // Return simulated win.ini content
        res.setHeader('Content-Type', 'text/plain')
        return res.status(200).send(`; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
`)
    }

    // Don't show generic path traversal message - let scanner mark as safe
    // Normal file request
    return res.status(200).send(`Notice: ${file}
This is a normal notice file.`)
}
