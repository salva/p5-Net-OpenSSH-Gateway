
use ExtUtils::MakeMaker;

WriteMakefile( NAME           => 'Net::OpenSSH::Gateway',
               VERSION_FROM   => 'lib/Net/OpenSSH/Gateway.pm',
               PREREQ_PM      => { 'App::pnc' => 0,
                                   'Net::OpenSSH' => '0.54' },
               ABSTRACT_FROM  => 'lib/Net/OpenSSH/Gateway.pm',
               AUTHOR         => 'Salvador Fandino <sfandino@yahoo.com>'
);
