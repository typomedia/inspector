<?php

namespace Typomedia\Inspector;

use Symfony\Component\Finder\Finder;

class Crawler
{
    private $endPoint = 'https://codeload.github.com/github/advisory-database/zip/main';
    
    public function parse(string $lockfile, string $whitelist): array
    {
        $lockContent = $this->getLockContents($lockfile);
        $decodeJson = json_decode($lockContent);

        $whitelistContent = $this->getWhitelistContents($whitelist);
        
        $this->extractTo($this->endPoint, '.');
        
        $path = './advisory-database-main/advisories/github-reviewed/';
        $finder = new Finder();
        $tmp = $finder->files()->in($path)->name('*.json')->depth('> 1');
        
        foreach ($tmp as $t) {
            $decodeOneJson = json_decode(file_get_contents($t));
            foreach ($decodeOneJson->affected as $affected) {
                if ($affected->package->ecosystem == 'Packagist' || $affected->package->ecosystem == 'npm') {
                    foreach ($affected->ranges as $range) {
                        if (isset($range->events[1]->fixed)) {
                            $packages[$affected->package->name][] = [
                                "introduced" => $range->events[0]->introduced,
                                "fixed" => $range->events[1]->fixed,
                                "data" => $decodeOneJson,
                            ];
                        }
                        else { // still present vulnerability
                            $packages[$affected->package->name][] = [
                                "introduced" => $range->events[0]->introduced,
                                "last_known_affected_version_range" => trim($affected->database_specific->last_known_affected_version_range, '<>= '),
                                "data" => $decodeOneJson,
                            ];
                        }
                    }
                }
            }
        }
        $vulnerabilities = [];
        foreach ($decodeJson->packages as $lockPackage) {
            $version = trim($lockPackage->version, 'v');
            if (isset($packages[$lockPackage->name])) {
                foreach ($packages[$lockPackage->name] as $vulnerability) {
                    $id = strtolower($vulnerability['data']->id);
                    $cve = strtolower($vulnerability['data']->aliases[0]);
                    $whitelist = array_map('strtolower', $whitelistContent['packages'][$lockPackage->name]['vuls']);

                    if (!in_array($id, $whitelist) && !in_array($cve, $whitelist)) {
                        if (version_compare($version, $vulnerability['introduced'], '>=') && version_compare($version, $vulnerability['fixed'], '<')) {
                            $vulnerabilities[$lockPackage->name . ' (' . $version . ')'][] = ($vulnerability);
                        }

                        if (version_compare($version, $vulnerability['introduced'], '>=') && version_compare($version, $vulnerability['last_known_affected_version_range'], '<=')) {
                            $vulnerabilities[$lockPackage->name . ' (' . $version . ')'][] = ($vulnerability);
                        }
                    }
                }
            }
        }
        return $vulnerabilities;
    }

    private function extractTo(string $fileUrl, string $path): void
    {
        @mkdir($path);
        $fileZip = $path . '/advisories.zip';
        if (!file_exists($fileZip) || time() > (filemtime($fileZip) + (60 * 60 * 2))) {
            file_put_contents($fileZip, file_get_contents($fileUrl));
            $zip = new \ZipArchive();
            if (file_exists($fileZip)) {
                if ($zip->open($fileZip)) {
                    $zip->extractTo($path);
                    $zip->close();
                } else {
                    throw new \Exception("Failed to open '$fileZip'");
                }
            } else {
                throw new \Exception("File doesn't exist. '$fileZip'");
            }
        }
    }
    
    private function getLockContents(string $lock): string
    {
        $contents = json_decode(file_get_contents($lock), true);
        $hash = $contents['content-hash'] ?? ($contents['hash'] ?? '');
        $packages = [
            'content-hash' => $hash,
            'packages' => [],
            'packages-dev' => []
        ];

        foreach (['packages'] as $key) {
            if (!\is_array($contents[$key])) {
                continue;
            }
            foreach ($contents[$key] as $package) {
                $data = [
                    'name' => $package['name'],
                    'version' => $package['version'],
                ];
                if (isset($package['time']) && false !== strpos($package['version'], 'dev')) {
                    $data['time'] = $package['time'];
                }
                $packages[$key][] = $data;
            }
        }
        
        return json_encode($packages);
    }

    /**
     * @param string $whitelist
     * @return array|array[]
     */
    private function getWhitelistContents(string $whitelist)
    {
        $contents = json_decode(file_get_contents($whitelist), true);
        $whitelist = [];

        foreach (['packages'] as $key) {
            if (!\is_array($contents[$key])) {
                continue;
            }
            foreach ($contents[$key] as $package) {
                $whitelist[$key][$package['name']] = [
                    'vuls' => $package['whitelist'],
                ];
            }
        }

        return $whitelist;
    }
}
