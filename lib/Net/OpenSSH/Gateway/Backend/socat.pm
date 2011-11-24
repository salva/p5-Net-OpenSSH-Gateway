package Net::OpenSSH::Gateway::Backend::socat;

use strict;
use warnings;

require Net::OpenSSH::Gateway::Backend;
our @ISA = qw(Net::OpenSSH::Gateway::Backend);

sub _default_command_names { { socat => [qw(socat)] } }

my %scheme2pproto = ( http => 'proxy-connect',
                      socks4 => 'socks4',
                      socks5 => 'socks5' );

sub check_args { 1 }

sub _command { 'socat' }

sub _command_args {
    my ($self, %opts) = @_;

    my @chain;
    my $host = $opts{host};
    my $port = $opts{port};
    for my $proxy (reverse @{$self->{proxies}}) {
        my $scheme = $proxy->{scheme};
        $scheme =~ s/s$//;
        my $proto = $scheme2pproto{$scheme};
        push @chain, "$proto:$host:$port";
        $proxy->{ssl} and push @chain, "openssl";
        $host = $proxy->{host};
        $port = $proxy->{port};
    }
    push @chain, "tcp:$host:$port";
    return ('-', join('|', @chain));
}

1;
