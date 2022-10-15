<?php

namespace Typomedia\Inspector\Tests;

use PHPUnit\Framework\TestCase;
use Typomedia\Inspector\Crawler;

class CrawlerTest extends TestCase
{
    public function testGetLock()
    {
        $crawler = new Crawler();
        $whitelist = $crawler->getWhitelist(__DIR__ . '/../example.json');
        $this->assertEquals(['GHSA-52m2-vc4m-jj33', 'CVE-2022-39261'], $whitelist['twig/twig']['vuls']);
        $lockfile = $crawler->getContents('composer.lock');
        $this->assertEquals(8, count($lockfile->packages));
    }
}
