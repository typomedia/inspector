<?php

namespace Typomedia\Inspector;

use Exception;
use RuntimeException;
use Symfony\Component\Finder\Finder;

class Crawler
{
    public const ENDPOINT = 'https://codeload.github.com/github/advisory-database/zip/main';

    public const ECOSYSTEMS = ['Packagist', 'npm'];

    /**
     * @var object
     */
    private object $packages;

    /**
     * @var array
     */
    private array $whitelist = [];

    /**
     * @var array
     */
    private array $advisories = [];

    /**
     * @var array
     */
    private array $vulnerabilities = [];

    /**
     * @param string $lockfile
     * @param string $whitelist
     * @return array
     * @throws Exception
     */
    public function parse(string $lockfile, string $whitelist): array
    {
        $this->extract(self::ENDPOINT);

        $finder = new Finder();
        $path = 'advisory-database-main/advisories/github-reviewed/';
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
                            $this->advisories[$affected->package->name][] = [
                                'intro' => $intro,
                                'fixed' => $fixed,
                                'data' => $advisory,
                            ];
                        }
                        // handle unfixed vulnerability
                        $this->advisories[$affected->package->name][] = [
                            'intro' => $intro,
                            'range' => trim((string) $range, '<>= '),
                            "data" => $advisory,
                        ];
                    }
                }
            }
        }

        $this->packages = $this->getContents($lockfile);
        $this->whitelist = $this->getWhitelist($whitelist);

        foreach ($this->packages->packages as $package) {
            $version = trim((string) $package->version, 'v');
            foreach ($this->advisories[$package->name] as $advisory) {
                $gid = strtolower((string) $advisory['data']->id);
                $cve = strtolower((string) $advisory['data']->aliases[0]);

                $vuls = $this->whitelist[$package->name]['vuls'];
                $whitelist = array_map('strtolower', $vuls);

                if (!in_array($gid, $whitelist, true) && !in_array($cve, $whitelist, true)) {
                    if (version_compare($version, $advisory['intro'] ?? '', '>=') &&
                        version_compare($version, $advisory['fixed'] ?? '', '<')) {
                        $this->vulnerabilities[$package->name . '@' . $version][] = ($advisory);
                    }

                    if (version_compare($version, $advisory['intro'] ?? '', '>=') &&
                        version_compare($version, $advisory['range'] ?? '', '<=')) {
                        $this->vulnerabilities[$package->name . '@' . $version][] = ($advisory);
                    }
                }
            }
        }

        return $this->vulnerabilities;
    }

    /**
     * @throws RuntimeException
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
                    throw new RuntimeException("Failed to open '$fileZip'");
                }
            } else {
                throw new RuntimeException("File doesn't exist. '$fileZip'");
            }
        }
    }

    /**
     * @param string $file
     * @return object
     */
    public function getContents(string $file)
    {
        return json_decode(file_get_contents($file), false);
    }

    /**
     * @param string $file
     * @return array
     */
    public function getWhitelist(string $file): array
    {
        $contents = $this->getContents($file);
        $whitelist = [];

        foreach ($contents->packages as $package) {
            $whitelist[$package->name] = [
                'vuls' => $package->whitelist ?? [],
            ];
        }

        return $whitelist;
    }
}
