<?php

namespace Typomedia\Inspector;

use Typomedia\Inspector\Exception\RuntimeException;

class Inspector
{
    const VERSION = '1.2.0';

    private $crawler;

    public function __construct(Crawler $crawler = null)
    {
        $this->crawler = null === $crawler ? new Crawler() : $crawler;
    }

    /**
     * @param string $lockfile
     * @param string $whitelist
     * @return array
     */
    public function check(string $lockfile, string $whitelist): array
    {
        if (!file_exists($lockfile)) {
            throw new RuntimeException(sprintf('The lock file "%s" does not exist.', $lockfile));
        }

        if (!file_exists($whitelist)) {
            throw new RuntimeException(sprintf('The whitelist file "%s" does not exist.', $whitelist));
        }

        return $this->crawler->parse($lockfile, $whitelist);
    }
}
