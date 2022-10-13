<?php

/*
 * This file is part of the SensioLabs Security Checker.
 *
 * (c) Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE.md
 * file that was distributed with this source code.
 */

namespace Typomedia\Inspector\Command;

use Typomedia\Inspector\Inspector;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class InspectorCommand extends Command
{
    /**
     * @var array
     */
    const SERVERITY = [
        'low'       => 1,
        'moderate'  => 2,
        'high'      => 3,
        'critical'  => 4
    ];

    /**
     * @var Inspector
     */
    private Inspector $inspector;

    /**
     * @param Inspector $inspector
     */
    public function __construct(Inspector $inspector)
    {
        $this->inspector = $inspector;
        parent::__construct();
    }

    /**
     * @see Command
     */
    protected function configure()
    {
        $this
            ->setName('check')
            ->setDescription('Checks vulnerabilities in your project dependencies')
            ->addArgument(
                'lockfile',
                InputArgument::OPTIONAL,
                'The path to the composer.lock file',
                'composer.lock'
            )
            ->addOption(
                'whitelist',
                'w',
                InputOption::VALUE_OPTIONAL,
                'The path to the whitelist.json file'
            )
            ->addOption(
                'severity',
                's',
                InputOption::VALUE_REQUIRED,
                'Defines the severity level',
                'low'
            )
            ->setHelp(<<<EOF
The <info>%command.name%</info> command looks for security issues in the
project dependencies:

<info>php %command.full_name%</info>

You can also pass the path to a <info>example.json</info> file as an argument:

<info>php %command.full_name% example.json</info>
EOF
            );
    }

    /**
     * @param InputInterface $input
     * @param OutputInterface $output
     * @return int
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $lockfile = $input->getArgument('lockfile');
        $severity = $input->getOption('severity');
        $whitelist = $input->getOption('whitelist') ?: $lockfile;
        $counter = 0;

        $vulnerabilities = $this->inspector->check($lockfile, $whitelist);

        $output->writeln('<comment># Github Advisory Database Report</comment>');
        if ($vulnerabilities) {
            foreach ($vulnerabilities as $key => $vuls) {
                $headline = true;
                foreach ($vuls as $vul) {
                    $severity1 = self::SERVERITY[strtolower(trim((string) $severity))];
                    $severity2 = self::SERVERITY[strtolower(trim((string) $vul['data']->database_specific->severity))];

                    if ($severity2 >= $severity1) {
                        if ($headline) { // Print headline only once
                            $counter ++;
                            $output->writeln('');
                            $output->writeln('<comment>## ' . $key . '</comment>');
                            $headline = false;
                        }

                        $output->writeln('');
                        $output->writeln('### [' . $vul['data']->database_specific->severity . '] ' . $vul['data']->id . ': ' . $vul['data']->summary);
                        foreach ($vul['data']->references as $reference) {
                            $output->writeln(' - <href=' . $reference->url . '>' . $reference->url . '</>');
                        }
                    }
                }
            }

            $output->writeln('');
            $output->writeln('<error>> ' . $counter . ' packages have known vulnerabilities</error>');
        } else {
            $output->writeln('');
            $output->writeln('<bg=green>No packages have known vulnerabilities.</>');
        }

        $exit = $counter > 0;
        return (int)$exit;
    }
}
