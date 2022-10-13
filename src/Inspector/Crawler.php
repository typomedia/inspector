<?php

namespace Typomedia\Inspector;

use Exception;
use Symfony\Component\Finder\Finder;

class Crawler
{
    public const ENDPOINT = 'https://codeload.github.com/github/advisory-database/zip/main';

    public const ECOSYSTEMS = ['Packagist', 'npm'];

    private array $packages = [];

    /**
     * @param string $lockfile
     * @param string $whitelist
     * @return array
     * @throws Exception
     */
    public function parse(string $lockfile, string $whitelist): array
    {
        $lockContent = $this->getLockContents($lockfile);
        $decodeJson = json_decode($lockContent);

        $whitelistContent = $this->getWhitelistContents($whitelist);

        $this->extract(self::ENDPOINT);

        $path = 'advisory-database-main/advisories/github-reviewed/';
        $finder = new Finder();
        $files = $finder->files()->in($path)->name('*.json')->depth('> 1');

        foreach ($files as $file) {
            $advisory = json_decode($file->getContents(), false);

            foreach ($advisory->affected as $affected) {
                $ecosystem = $affected->package->ecosystem;
                if (in_array($ecosystem, self::ECOSYSTEMS, true)) {
                    foreach ($affected->ranges as $range) {
                        $fixed = $range->events[1]->fixed;
                        $intro = $range->events[0]->introduced;
                        $range = $affected->database_specific->last_known_affected_version_range;
                        if (isset($fixed)) {
                            $this->packages[$affected->package->name][] = [
                                'intro' => $intro,
                                'fixed' => $fixed,
                                'data' => $advisory,
                            ];
                        }
                        // still unfixed vulnerability
                        $this->packages[$affected->package->name][] = [
                            'intro' => $intro,
                            'range' => trim((string) $range, '<>= '),
                            "data" => $advisory,
                        ];
                    }
                }
            }
        }

        $vulnerabilities = [];
        foreach ($decodeJson->packages as $lockPackage) {
            $version = trim((string) $lockPackage->version, 'v');
            if (isset($this->packages[$lockPackage->name])) {
                foreach ($this->packages[$lockPackage->name] as $vulnerability) {
                    $id = strtolower((string) $vulnerability['data']->id);
                    $cve = strtolower((string) $vulnerability['data']->aliases[0]);
                    $vuls = $whitelistContent['packages'][$lockPackage->name]['vuls'];
                    $whitelist = array_map('strtolower', $vuls ?: []);

                    if (!in_array($id, $whitelist) && !in_array($cve, $whitelist)) {
                        if (version_compare($version, $vulnerability['intro'] ?? '', '>=') && version_compare($version, $vulnerability['fixed'] ?? '', '<')) {
                            $vulnerabilities[$lockPackage->name . ' (' . $version . ')'][] = ($vulnerability);
                        }

                        if (version_compare($version, $vulnerability['intro'] ?? '', '>=') && version_compare($version, $vulnerability['range'] ?? '', '<=')) {
                            $vulnerabilities[$lockPackage->name . ' (' . $version . ')'][] = ($vulnerability);
                        }
                    }
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * @throws Exception
     */
    private function extract(string $fileUrl): void
    {
        $fileZip = 'advisories.zip';
        if (!file_exists($fileZip) || time() > (filemtime($fileZip) + (60 * 60 * 2))) {
            file_put_contents($fileZip, file_get_contents($fileUrl));
            $zip = new \ZipArchive();
            if (file_exists($fileZip)) {
                if ($zip->open($fileZip)) {
                    $zip->extractTo('.');
                    $zip->close();
                } else {
                    throw new Exception("Failed to open '$fileZip'");
                }
            } else {
                throw new Exception("File doesn't exist. '$fileZip'");
            }
        }
    }

    /**
     * @param string $lock
     * @return string
     */
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
    private function getWhitelistContents(string $whitelist): array
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
