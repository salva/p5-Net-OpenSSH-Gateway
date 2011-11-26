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
    my $host = $self->_slave_quote_opt(host => %opts);
    my $port = $self->_slave_quote_opt(port => %opts);
    for my $proxy (reverse @{$self->{proxies}}) {
        my $scheme = $proxy->{scheme};
        $scheme =~ s/s$//;
        my $proto = $self->_slave_quote($scheme2pproto{$scheme});
        push @chain, "$proto:$host:$port";
        $proxy->{ssl} and push @chain, "openssl";
        $host = $self->_slave_quote($proxy->{host});
        $port = $self->_slave_quote($proxy->{port});
    }
    push @chain, "tcp:$host:$port";
    return ('-', join('|', @chain));
}

sub _command_version_args { '-V' }

sub _check_command_version_output {
    my ($self, $text) = @_;
    if (my ($ver) = /^socat version (\S+)/) {
        print "socat version $ver found\n";
        return 1
    }
    return
}

1;
